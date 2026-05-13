"""
Network flow classifier — loads the trained RandomForest model
and predicts attack types from network flow features.
"""
import os
import joblib
import numpy as np
import pandas as pd
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

# Lazy-loaded globals
_model = None
_encoder = None
_scaler = None
_feature_cols = None


def _load_model():
    """Lazy-load the network model artifacts."""
    global _model, _encoder, _scaler, _feature_cols

    if _model is None:
        _model = joblib.load(str(PROJECT_ROOT / "network_model.pkl"))
        _encoder = joblib.load(str(PROJECT_ROOT / "network_label_encoder.pkl"))
        _scaler = joblib.load(str(PROJECT_ROOT / "network_scaler.pkl"))
        _feature_cols = joblib.load(str(PROJECT_ROOT / "network_feature_cols.pkl"))

    return _model, _encoder, _scaler, _feature_cols


def detect_from_flow(flow_features):
    """
    Classify a single network flow.

    Args:
        flow_features: dict with flow feature values (keys match UNSW-NB15 column names)

    Returns:
        dict with attack_type, confidence, mitre_id, tactic, severity, source_type
    """
    from analysis.network_mitre_map import (
        NETWORK_ATTACK_TO_MITRE,
        ATTACK_SEVERITY,
        TECHNIQUE_TO_TACTIC,
    )

    model, encoder, scaler, feature_cols = _load_model()

    # Build feature vector from dict
    values = [float(flow_features.get(col, 0)) for col in feature_cols]
    X = np.array(values).reshape(1, -1)

    # Replace inf/nan
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

    # Scale
    X_scaled = scaler.transform(X)

    # Predict
    prediction = model.predict(X_scaled)[0]
    probabilities = model.predict_proba(X_scaled)[0]
    confidence = round(float(probabilities.max()) * 100, 2)

    attack_type = encoder.inverse_transform([prediction])[0]
    mitre_id = NETWORK_ATTACK_TO_MITRE.get(attack_type)
    severity = ATTACK_SEVERITY.get(attack_type, "Unknown")
    tactic = TECHNIQUE_TO_TACTIC.get(mitre_id, "Unknown") if mitre_id else "None"

    return {
        "attack_type": attack_type,
        "confidence": confidence,
        "severity": severity,
        "mitre_id": mitre_id or "N/A",
        "tactic": tactic,
        "source_type": "network",
    }


def detect_from_dataframe(df):
    """
    Batch classify network flows from a DataFrame.

    Args:
        df: pandas DataFrame with flow features (columns matching UNSW-NB15 format).
            Can include extra columns — only model features will be used.

    Returns:
        List of dicts, each with: attack_type, confidence, severity,
        mitre_id, tactic, source_type
    """
    from analysis.network_mitre_map import (
        NETWORK_ATTACK_TO_MITRE,
        ATTACK_SEVERITY,
        TECHNIQUE_TO_TACTIC,
    )

    model, encoder, scaler, feature_cols = _load_model()

    # Extract and align feature columns
    X = pd.DataFrame(index=df.index)
    for col in feature_cols:
        if col in df.columns:
            X[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)
        else:
            X[col] = 0

    # Replace inf
    X = X.replace([np.inf, -np.inf], 0)

    # Scale
    X_scaled = scaler.transform(X.values)

    # Predict
    predictions = model.predict(X_scaled)
    probabilities = model.predict_proba(X_scaled)

    results = []
    for i, (pred, proba) in enumerate(zip(predictions, probabilities)):
        confidence = round(float(proba.max()) * 100, 2)
        attack_type = encoder.inverse_transform([pred])[0]
        mitre_id = NETWORK_ATTACK_TO_MITRE.get(attack_type)
        severity = ATTACK_SEVERITY.get(attack_type, "Unknown")
        tactic = TECHNIQUE_TO_TACTIC.get(mitre_id, "Unknown") if mitre_id else "None"

        results.append({
            "attack_type": attack_type,
            "confidence": confidence,
            "severity": severity,
            "mitre_id": mitre_id or "N/A",
            "tactic": tactic,
            "source_type": "network",
        })

    return results
