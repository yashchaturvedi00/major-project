"""
Log / network flow ingestion module.

Reads UNSW-NB15 format CSVs and normalizes column names
for compatibility with the network IDS model.
"""
import os
import pandas as pd
import numpy as np


# ── Feature columns used by the network model ───────────────
# These are the numeric + encoded features from UNSW-NB15
NUMERIC_FEATURES = [
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

CATEGORICAL_FEATURES = ["proto", "state", "service"]

# Columns that are metadata, not features
META_COLUMNS = ["srcip", "sport", "dstip", "dsport", "Stime", "Ltime",
                "attack_cat", "label", "id"]


def ingest_csv(file_path):
    """
    Read a UNSW-NB15 format CSV and return a cleaned DataFrame.

    Args:
        file_path: Path to the CSV file

    Returns:
        Tuple of (features_df, meta_df) where features_df has model-ready
        columns and meta_df has metadata like IPs, ports, labels.
    """
    # Read with flexible parsing
    df = pd.read_csv(file_path, low_memory=False)

    # Strip whitespace from column names
    df.columns = df.columns.str.strip()

    # Clean attack_cat if present
    if "attack_cat" in df.columns:
        df["attack_cat"] = df["attack_cat"].fillna("Normal").str.strip()
        # Standardize empty strings to "Normal"
        df.loc[df["attack_cat"] == "", "attack_cat"] = "Normal"

    # Separate metadata
    meta_cols = [c for c in META_COLUMNS if c in df.columns]
    meta_df = df[meta_cols].copy() if meta_cols else pd.DataFrame(index=df.index)

    # Extract feature columns
    feature_cols = []
    for col in NUMERIC_FEATURES:
        if col in df.columns:
            feature_cols.append(col)

    features_df = df[feature_cols].copy()

    # Convert all to numeric, coerce errors
    for col in features_df.columns:
        features_df[col] = pd.to_numeric(features_df[col], errors="coerce")

    # Replace inf with NaN, then fill NaN with 0
    features_df = features_df.replace([np.inf, -np.inf], np.nan)
    features_df = features_df.fillna(0)

    # Handle categorical features (one-hot encode)
    for cat_col in CATEGORICAL_FEATURES:
        if cat_col in df.columns:
            dummies = pd.get_dummies(df[cat_col], prefix=cat_col, dtype=int)
            features_df = pd.concat([features_df, dummies], axis=1)

    return features_df, meta_df


def ingest_log_file(file_path):
    """
    Read a log file and attempt to parse it as CSV or structured log.

    Supports:
    - UNSW-NB15 CSV format
    - Generic CSV with network flow fields

    Returns:
        Tuple of (features_df, meta_df)
    """
    ext = os.path.splitext(file_path)[1].lower()

    if ext in (".csv", ".tsv"):
        return ingest_csv(file_path)
    else:
        raise ValueError(f"Unsupported log format: {ext}. Use CSV files.")


def get_expected_features():
    """Return the list of numeric feature names the model expects."""
    return NUMERIC_FEATURES.copy()
