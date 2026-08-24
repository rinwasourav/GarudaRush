"""
DDoS Detection Model — RandomForest Trainer & Predictor
=========================================================
Generates synthetic training data or loads CICIDS dataset, trains a
RandomForestClassifier, evaluates it, and persists model & scaler to disk.

Usage:
    python ml_model.py          # Train and save model
    python ml_model.py --test   # Sanity check predictions
"""

import os
import sys
import logging
import argparse
import glob
import numpy as np
import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────
MODEL_PATH = os.getenv("MODEL_PATH", "ddos_rf_model.pkl")
SCALER_PATH = os.getenv("SCALER_PATH", "ddos_scaler.pkl")
RANDOM_SEED = 42

logging.basicConfig(level=logging.INFO, format="%(asctime)s - [ML] - %(message)s")
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# Feature Schema
# ─────────────────────────────────────────────
FEATURE_COLUMNS = [
    "packet_rate",       # idx 0
    "byte_rate",         # idx 1
    "syn_count",         # idx 2
    "syn_ack_ratio",     # idx 3
    "icmp_count",        # idx 4
    "udp_count",         # idx 5
    "tcp_count",         # idx 6
    "fragment_count",    # idx 7
    "http_requests",     # idx 8
    "src_ip_entropy",    # idx 9
    "unique_dst_ports",  # idx 10
]


# ─────────────────────────────────────────────
# Synthetic Dataset Generator
# ─────────────────────────────────────────────
def generate_dataset(n_normal: int = 4000, n_ddos: int = 4000, seed: int = RANDOM_SEED) -> pd.DataFrame:
    """
    Simulates realistic normal network flows and four major DDoS attack patterns:
      • SYN Flood  – High SYN burst, unbalanced ratio, low IP entropy
      • UDP Flood  – High UDP packet rate and bandwidth consumption
      • ICMP Flood – Extreme ICMP packet density
      • HTTP Flood – High HTTP request volume over TCP
    """
    rng = np.random.default_rng(seed)

    # Normal traffic
    normal = pd.DataFrame({
        "packet_rate": rng.normal(200, 60, n_normal).clip(10),
        "byte_rate": rng.normal(50_000, 15_000, n_normal).clip(1000),
        "syn_count": rng.poisson(15, n_normal).astype(float),
        "syn_ack_ratio": rng.normal(1.1, 0.3, n_normal).clip(0.5, 3),
        "icmp_count": rng.poisson(5, n_normal).astype(float),
        "udp_count": rng.poisson(40, n_normal).astype(float),
        "tcp_count": rng.poisson(130, n_normal).astype(float),
        "fragment_count": rng.poisson(3, n_normal).astype(float),
        "http_requests": rng.poisson(25, n_normal).astype(float),
        "src_ip_entropy": rng.normal(3.5, 0.5, n_normal).clip(1, 5),
        "unique_dst_ports": rng.integers(3, 15, n_normal).astype(float),
        "label": 0,
    })

    per_type = n_ddos // 4
    remainder = n_ddos - per_type * 4

    # SYN Flood
    syn = pd.DataFrame({
        "packet_rate": rng.normal(8000, 2000, per_type).clip(1000),
        "byte_rate": rng.normal(600_000, 100_000, per_type).clip(50_000),
        "syn_count": rng.normal(5000, 1000, per_type).clip(500),
        "syn_ack_ratio": rng.normal(50, 10, per_type).clip(5),
        "icmp_count": rng.poisson(5, per_type).astype(float),
        "udp_count": rng.poisson(20, per_type).astype(float),
        "tcp_count": rng.normal(7000, 1500, per_type).clip(500),
        "fragment_count": rng.poisson(5, per_type).astype(float),
        "http_requests": rng.poisson(10, per_type).astype(float),
        "src_ip_entropy": rng.normal(1.2, 0.4, per_type).clip(0, 5),
        "unique_dst_ports": rng.integers(1, 4, per_type).astype(float),
        "label": 1,
    })

    # UDP Flood
    udp = pd.DataFrame({
        "packet_rate": rng.normal(12000, 3000, per_type).clip(2000),
        "byte_rate": rng.normal(5_000_000, 500_000, per_type).clip(200_000),
        "syn_count": rng.poisson(10, per_type).astype(float),
        "syn_ack_ratio": rng.normal(1.0, 0.2, per_type).clip(0.5, 2),
        "icmp_count": rng.poisson(8, per_type).astype(float),
        "udp_count": rng.normal(11000, 2000, per_type).clip(500),
        "tcp_count": rng.poisson(30, per_type).astype(float),
        "fragment_count": rng.normal(200, 50, per_type).clip(10),
        "http_requests": rng.poisson(5, per_type).astype(float),
        "src_ip_entropy": rng.normal(2.0, 0.6, per_type).clip(0, 5),
        "unique_dst_ports": rng.integers(1, 5, per_type).astype(float),
        "label": 1,
    })

    # ICMP Flood
    icmp = pd.DataFrame({
        "packet_rate": rng.normal(6000, 1500, per_type).clip(500),
        "byte_rate": rng.normal(300_000, 60_000, per_type).clip(10_000),
        "syn_count": rng.poisson(8, per_type).astype(float),
        "syn_ack_ratio": rng.normal(1.0, 0.2, per_type).clip(0.5, 2),
        "icmp_count": rng.normal(5500, 1000, per_type).clip(500),
        "udp_count": rng.poisson(15, per_type).astype(float),
        "tcp_count": rng.poisson(20, per_type).astype(float),
        "fragment_count": rng.poisson(4, per_type).astype(float),
        "http_requests": rng.poisson(3, per_type).astype(float),
        "src_ip_entropy": rng.normal(1.5, 0.4, per_type).clip(0, 5),
        "unique_dst_ports": rng.integers(1, 3, per_type).astype(float),
        "label": 1,
    })

    # HTTP Flood
    extra = per_type + remainder
    http = pd.DataFrame({
        "packet_rate": rng.normal(3000, 700, extra).clip(500),
        "byte_rate": rng.normal(400_000, 80_000, extra).clip(20_000),
        "syn_count": rng.normal(800, 200, extra).clip(50),
        "syn_ack_ratio": rng.normal(4.5, 1.0, extra).clip(1),
        "icmp_count": rng.poisson(5, extra).astype(float),
        "udp_count": rng.poisson(20, extra).astype(float),
        "tcp_count": rng.normal(2800, 600, extra).clip(100),
        "fragment_count": rng.poisson(4, extra).astype(float),
        "http_requests": rng.normal(2500, 500, extra).clip(100),
        "src_ip_entropy": rng.normal(2.8, 0.5, extra).clip(0, 5),
        "unique_dst_ports": rng.integers(1, 4, extra).astype(float),
        "label": 1,
    })

    df = pd.concat([normal, syn, udp, icmp, http], ignore_index=True)
    df = df.astype({c: float for c in FEATURE_COLUMNS})
    df["label"] = df["label"].astype(int)
    return df.sample(frac=1, random_state=seed).reset_index(drop=True)


# ─────────────────────────────────────────────
# Training Engine
# ─────────────────────────────────────────────
def load_cicids_dataset(files: list, n_normal: int, n_ddos: int) -> pd.DataFrame:
    logger.info(f"Loading data from {len(files)} CSV dataset files...")
    all_chunks = []

    for f in files:
        logger.info(f"Reading sample from {f}...")
        try:
            df_chunk = pd.read_csv(f, nrows=50000, low_memory=False)
            df_chunk.columns = [c.strip() for c in df_chunk.columns]

            required = [
                "Destination Port", "Flow Packets/s", "Flow Bytes/s",
                "SYN Flag Count", "ACK Flag Count", "Total Fwd Packets",
                "Total Backward Packets", "Label"
            ]
            missing = [c for c in required if c not in df_chunk.columns]
            if missing:
                logger.warning(f"Missing required columns {missing} in {f}, skipping...")
                continue

            df_chunk.replace([np.inf, -np.inf], np.nan, inplace=True)
            df_chunk.dropna(subset=required, inplace=True)
            df_chunk['Label'] = df_chunk['Label'].apply(lambda x: 0 if str(x).upper() == 'BENIGN' else 1)
            all_chunks.append(df_chunk)
        except Exception as e:
            logger.error(f"Failed to read {f}: {e}")

    if not all_chunks:
        return None

    df_c = pd.concat(all_chunks, ignore_index=True)
    logger.info(f"Loaded {len(df_c)} candidate rows. Normal={sum(df_c['Label']==0)}, DDoS={sum(df_c['Label']==1)}")

    df_normal = df_c[df_c['Label'] == 0]
    df_ddos = df_c[df_c['Label'] == 1]

    n_sample_normal = min(n_normal, len(df_normal))
    n_sample_ddos = min(n_ddos, len(df_ddos))

    if n_sample_normal > 0:
        df_normal = df_normal.sample(n=n_sample_normal, random_state=RANDOM_SEED)
    if n_sample_ddos > 0:
        df_ddos = df_ddos.sample(n=n_sample_ddos, random_state=RANDOM_SEED)

    df_c = pd.concat([df_normal, df_ddos], ignore_index=True).sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)

    df_out = pd.DataFrame()
    df_out["packet_rate"] = df_c["Flow Packets/s"].astype(float)
    df_out["byte_rate"] = df_c["Flow Bytes/s"].astype(float)
    df_out["syn_count"] = df_c["SYN Flag Count"].astype(float)

    ack_count = df_c["ACK Flag Count"].replace(0, 1).astype(float)
    df_out["syn_ack_ratio"] = df_out["syn_count"] / ack_count

    total_packets = df_c["Total Fwd Packets"] + df_c["Total Backward Packets"]
    is_tcp = df_c["Destination Port"].isin([80, 443, 22, 21, 23, 110, 143])
    df_out["tcp_count"] = np.where(is_tcp, total_packets, 0).astype(float)

    is_udp = df_c["Destination Port"].isin([53, 123])
    df_out["udp_count"] = np.where(is_udp, total_packets, 0).astype(float)

    is_icmp = df_c["Destination Port"] == 0
    df_out["icmp_count"] = np.where(is_icmp, df_c["Total Fwd Packets"], 0).astype(float)
    df_out["fragment_count"] = 0.0

    is_http = df_c["Destination Port"].isin([80, 443])
    df_out["http_requests"] = np.where(is_http, df_c["Total Fwd Packets"], 0).astype(float)
    df_out["src_ip_entropy"] = 3.5
    df_out["unique_dst_ports"] = 1.0
    df_out["label"] = df_c["Label"].astype(int)

    return df_out


def train(n_normal: int = 50000, n_ddos: int = 50000):
    csv_files = glob.glob("*.csv")
    df = None
    if csv_files:
        df = load_cicids_dataset(csv_files, n_normal, n_ddos)

    if df is None:
        logger.info("Generating synthetic dataset for model training...")
        df = generate_dataset(n_normal, n_ddos)

    X = df[FEATURE_COLUMNS].values
    y = df["label"].values

    logger.info(f"Dataset summary: {len(df)} samples | Normal={sum(y==0)}, DDoS={sum(y==1)}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=RANDOM_SEED
    )

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    logger.info("Training RandomForestClassifier...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_split=4,
        min_samples_leaf=2,
        max_features="sqrt",
        class_weight="balanced",
        n_jobs=-1,
        random_state=RANDOM_SEED,
    )
    model.fit(X_train_s, y_train)

    y_pred = model.predict(X_test_s)
    y_proba = model.predict_proba(X_test_s)[:, 1]

    logger.info("\n" + classification_report(y_test, y_pred, target_names=["Normal", "DDoS"]))
    logger.info(f"Confusion Matrix:\n{confusion_matrix(y_test, y_pred)}")
    logger.info(f"ROC-AUC: {roc_auc_score(y_test, y_proba):.4f}")

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_SEED)
    cv_scores = cross_val_score(model, X_train_s, y_train, cv=cv, scoring="roc_auc")
    logger.info(f"5-Fold CV ROC-AUC: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    logger.info(f"Model serialized → {MODEL_PATH}")
    logger.info(f"Scaler serialized → {SCALER_PATH}")

    return model, scaler


# ─────────────────────────────────────────────
# Real-Time Predictor Interface
# ─────────────────────────────────────────────
class DDoSDetector:
    """
    Real-time inference wrapper loaded by the central Flask server.
    Thread-safe & non-blocking.
    """

    def __init__(self, model_path: str = MODEL_PATH, scaler_path: str = SCALER_PATH):
        self.model_path = model_path
        self.scaler_path = scaler_path
        self._model = None
        self._scaler = None
        self._loaded = False
        self._load()

    def _load(self):
        try:
            self._model = joblib.load(self.model_path)
            self._scaler = joblib.load(self.scaler_path)
            self._loaded = True
            logger.info("DDoS detection model loaded successfully.")
        except FileNotFoundError:
            logger.warning(
                "Model file not found. Run `python ml_model.py` to train model. "
                "Predictions will be skipped until available."
            )

    def is_ready(self) -> bool:
        return self._loaded

    @staticmethod
    def extract_features(flow: dict) -> list:
        top_ports = flow.get("top_destination_ports", {})
        unique_dst_ports = len(top_ports)

        return [
            flow.get("packet_rate", 0.0),
            flow.get("byte_rate", 0.0),
            float(flow.get("syn_count", 0)),
            flow.get("syn_ack_ratio", 1.0),
            float(flow.get("icmp_count", 0)),
            float(flow.get("udp_count", 0)),
            float(flow.get("tcp_count", 0)),
            float(flow.get("fragment_count", 0)),
            float(flow.get("http_requests", 0)),
            flow.get("src_ip_entropy", 0.0),
            float(unique_dst_ports),
        ]

    def predict(self, flow: dict) -> dict:
        if not self._loaded:
            return {"error": "Model not loaded", "is_ddos": False, "confidence": 0.0}

        features = self.extract_features(flow)
        X = np.array(features, dtype=float).reshape(1, -1)
        X_scaled = self._scaler.transform(X)

        pred = int(self._model.predict(X_scaled)[0])
        proba = float(self._model.predict_proba(X_scaled)[0][1])

        attack_type = "none"
        if pred == 1:
            attack_type = self._classify_attack_type(features)

        return {
            "is_ddos": bool(pred),
            "confidence": round(proba, 4),
            "attack_type": attack_type,
            "features": dict(zip(FEATURE_COLUMNS, features)),
        }

    @staticmethod
    def _classify_attack_type(features: list) -> str:
        vals = dict(zip(FEATURE_COLUMNS, features))

        if vals["syn_count"] > 1000 and vals["syn_ack_ratio"] > 10:
            return "syn_flood"
        if vals["udp_count"] > 5000:
            return "udp_flood"
        if vals["icmp_count"] > 3000:
            return "icmp_flood"
        if vals["http_requests"] > 1000:
            return "http_flood"
        return "unknown_flood"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DDoS RF Model Trainer")
    parser.add_argument("--test", action="store_true", help="Run quick prediction test after training")
    parser.add_argument("--n-normal", type=int, default=50000)
    parser.add_argument("--n-ddos", type=int, default=50000)
    args = parser.parse_args()

    model, scaler = train(args.n_normal, args.n_ddos)

    if args.test:
        detector = DDoSDetector()
        normal_flow = {
            "packet_rate": 180, "byte_rate": 45000, "syn_count": 12,
            "syn_ack_ratio": 1.1, "icmp_count": 3, "udp_count": 35,
            "tcp_count": 120, "fragment_count": 2, "http_requests": 20,
            "src_ip_entropy": 3.4, "top_destination_ports": {"80": 30, "443": 20},
        }
        ddos_flow = {
            "packet_rate": 9500, "byte_rate": 700_000, "syn_count": 6000,
            "syn_ack_ratio": 65, "icmp_count": 5, "udp_count": 10,
            "tcp_count": 8500, "fragment_count": 3, "http_requests": 5,
            "src_ip_entropy": 1.1, "top_destination_ports": {"80": 9000},
        }
        logger.info(f"Normal flow prediction: {detector.predict(normal_flow)}")
        logger.info(f"DDoS flood prediction:   {detector.predict(ddos_flow)}")
