"""
Train the Network IDS model on the UNSW-NB15 dataset.

Uses RandomForestClassifier on 38+ numeric flow features to classify
network traffic into 9 attack categories + Normal.

Usage:
    python scripts/train_network_model.py

Prerequisites:
    Download UNSW-NB15 dataset and place the training/testing CSV files in:
        Dataset/network/UNSW_NB15_training-set.csv
        Dataset/network/UNSW_NB15_testing-set.csv

    Download from: https://research.unsw.edu.au/projects/unsw-nb15-dataset
    Or Kaggle:     https://www.kaggle.com/mrwellsdavid/unsw-nb15
"""
import os
import sys
import pandas as pd
import numpy as np
import joblib
from pathlib import Path

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.calibration import CalibratedClassifierCV

# ── Project path setup ───────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
os.chdir(PROJECT_ROOT)

from analysis.network_mitre_map import NETWORK_ATTACK_TO_MITRE, ATTACK_SEVERITY

print("=" * 60)
print("  NETWORK IDS MODEL TRAINING")
print("  Dataset: UNSW-NB15")
print("  Algorithm: RandomForestClassifier")
print("=" * 60)

# ── 1. Load dataset ──────────────────────────────────────────
print("\n[1/7] Loading UNSW-NB15 dataset...")

TRAIN_PATH = PROJECT_ROOT / "Dataset" / "network" / "UNSW-NB15" / "UNSW_NB15_training-set.csv"
TEST_PATH = PROJECT_ROOT / "Dataset" / "network" / "UNSW-NB15" / "UNSW_NB15_testing-set.csv"

if not TRAIN_PATH.exists():
    print(f"\n  ❌ Training set not found at: {TRAIN_PATH}")
    print("  Please download the UNSW-NB15 dataset and place the files in:")
    print(f"    {PROJECT_ROOT / 'Dataset' / 'network' / ''}")
    print("  Required files:")
    print("    - UNSW_NB15_training-set.csv")
    print("    - UNSW_NB15_testing-set.csv")
    print("\n  Download from:")
    print("    https://research.unsw.edu.au/projects/unsw-nb15-dataset")
    print("    https://www.kaggle.com/mrwellsdavid/unsw-nb15")
    sys.exit(1)

df_train = pd.read_csv(TRAIN_PATH, low_memory=False)
df_test = pd.read_csv(TEST_PATH, low_memory=False)

# Strip column name whitespace
df_train.columns = df_train.columns.str.strip()
df_test.columns = df_test.columns.str.strip()

print(f"  Training samples: {df_train.shape[0]}")
print(f"  Testing samples:  {df_test.shape[0]}")

# ── 2. Clean and prepare labels ──────────────────────────────
print("\n[2/7] Preparing labels...")

# Clean attack_cat column
for df in [df_train, df_test]:
    df["attack_cat"] = df["attack_cat"].fillna("Normal").str.strip()
    df.loc[df["attack_cat"] == "", "attack_cat"] = "Normal"
    # Fix inconsistent naming (some rows have extra spaces or variations)
    df["attack_cat"] = df["attack_cat"].replace({
        "Backdoor": "Backdoors",
        " Fuzzers": "Fuzzers",
        " Reconnaissance": "Reconnaissance",
        " Shellcode": "Shellcode",
    })

print(f"  Attack category distribution (training):")
for cat, count in df_train["attack_cat"].value_counts().items():
    severity = ATTACK_SEVERITY.get(cat, "Unknown")
    mitre = NETWORK_ATTACK_TO_MITRE.get(cat, "N/A")
    print(f"    {cat:20s} → {count:6d} samples  (MITRE: {mitre}, Severity: {severity})")

# ── 3. Select features ──────────────────────────────────────
print("\n[3/7] Selecting features...")

# Numeric features from UNSW-NB15
FEATURE_COLS = [
    "dur", "sbytes", "dbytes", "sttl", "dttl", "sloss", "dloss",
    "Sload", "Dload", "Spkts", "Dpkts", "swin", "dwin",
    "stcpb", "dtcpb", "smeansz", "dmeansz", "trans_depth",
    "res_bdy_len", "Sjit", "Djit", "Sintpkt", "Dintpkt",
    "tcprtt", "synack", "ackdat", "is_sm_ips_ports",
    "ct_state_ttl", "ct_flw_http_mthd", "is_ftp_login",
    "ct_ftp_cmd", "ct_srv_src", "ct_srv_dst", "ct_dst_ltm",
    "ct_src_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm",
    "ct_dst_src_ltm",
]

# Only use columns that exist in the dataset
available_cols = [c for c in FEATURE_COLS if c in df_train.columns]
missing_cols = [c for c in FEATURE_COLS if c not in df_train.columns]
if missing_cols:
    print(f"  ⚠ Missing columns (will skip): {missing_cols}")

print(f"  Using {len(available_cols)} numeric features")

X_train = df_train[available_cols].copy()
X_test = df_test[available_cols].copy()
y_train_labels = df_train["attack_cat"].copy()
y_test_labels = df_test["attack_cat"].copy()

# ── 4. Clean numeric data ───────────────────────────────────
print("\n[4/7] Cleaning and scaling features...")

# Convert to numeric, replace inf/nan
for df_feat in [X_train, X_test]:
    for col in df_feat.columns:
        df_feat[col] = pd.to_numeric(df_feat[col], errors="coerce")
    df_feat.replace([np.inf, -np.inf], np.nan, inplace=True)
    df_feat.fillna(0, inplace=True)

# Scale features
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

print(f"  Feature matrix shape: {X_train_scaled.shape}")

# ── 5. Encode labels ────────────────────────────────────────
print("\n[5/7] Encoding labels...")

encoder = LabelEncoder()
y_train = encoder.fit_transform(y_train_labels)
y_test = encoder.transform(y_test_labels)

print(f"  Number of classes: {len(encoder.classes_)}")
for i, cls in enumerate(encoder.classes_):
    print(f"    [{i}] {cls}")

# ── 6. Train model ──────────────────────────────────────────
print("\n[6/7] Training RandomForest classifier...")

model = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    min_samples_split=5,
    min_samples_leaf=2,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced",
)

model.fit(X_train_scaled, y_train)

# Evaluate
train_acc = model.score(X_train_scaled, y_train)
test_acc = model.score(X_test_scaled, y_test)

print(f"\n  Training Accuracy: {train_acc * 100:.2f}%")
print(f"  Testing Accuracy:  {test_acc * 100:.2f}%")

# Classification report
print("\n  Classification Report:")
y_pred = model.predict(X_test_scaled)
print(classification_report(y_test, y_pred, target_names=encoder.classes_))

# Top 10 most important features
print("  Top 10 Most Important Features:")
importances = model.feature_importances_
indices = np.argsort(importances)[::-1][:10]
for rank, idx in enumerate(indices, 1):
    print(f"    {rank}. {available_cols[idx]:25s} → importance: {importances[idx]:.4f}")

# ── 7. Save model artifacts ─────────────────────────────────
print("\n[7/7] Saving model artifacts...")

# Save to project root
joblib.dump(model, str(PROJECT_ROOT / "network_model.pkl"))
joblib.dump(encoder, str(PROJECT_ROOT / "network_label_encoder.pkl"))
joblib.dump(scaler, str(PROJECT_ROOT / "network_scaler.pkl"))

# Save the feature column list for inference
joblib.dump(available_cols, str(PROJECT_ROOT / "network_feature_cols.pkl"))

print(f"  Saved: network_model.pkl")
print(f"  Saved: network_label_encoder.pkl")
print(f"  Saved: network_scaler.pkl")
print(f"  Saved: network_feature_cols.pkl")

print("\n" + "=" * 60)
print(f"  ✅ Network IDS model trained successfully!")
print(f"  📊 Test Accuracy: {test_acc * 100:.2f}%")
print(f"  🎯 {len(encoder.classes_)} Attack Categories: {list(encoder.classes_)}")
print("=" * 60)
