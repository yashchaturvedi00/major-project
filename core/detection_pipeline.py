"""
Unified detection pipeline — routes inputs to the correct detector
(document scanner or network IDS) and enriches results with MITRE ATT&CK info.
"""
import os
import time
from pathlib import Path
from datetime import datetime

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def detect(input_path, input_type="auto"):
    """
    Run detection on a file, auto-routing to the correct detector.

    Args:
        input_path: Path to the file to analyze
        input_type: "document", "network_csv", or "auto" (detect by extension)

    Returns:
        List of detection result dicts, each with:
            attack_type, confidence, severity, mitre_id, tactic, source_type, etc.
    """
    if input_type == "auto":
        input_type = _detect_input_type(input_path)

    if input_type == "document":
        return _detect_document(input_path)
    elif input_type == "network_csv":
        return _detect_network(input_path)
    else:
        raise ValueError(f"Unknown input_type: {input_type}")


def _detect_input_type(file_path):
    """Auto-detect whether a file is a document or network log."""
    ext = os.path.splitext(file_path)[1].lower()

    # If it's a CSV, peek at columns to decide
    if ext == ".csv":
        import pandas as pd
        try:
            df = pd.read_csv(file_path, nrows=5, low_memory=False)
            df.columns = df.columns.str.strip()
            # Check for UNSW-NB15 network flow columns
            network_indicators = {"sbytes", "dbytes", "sttl", "dttl", "Spkts", "Dpkts"}
            if network_indicators.intersection(set(df.columns)):
                return "network_csv"
        except Exception:
            pass

    # Default to document
    return "document"


def _detect_document(file_path):
    """Run document scanner on a single file."""
    from core.folder_watcher import scan_file

    result = scan_file(file_path)
    if result.get("status") == "scanned":
        result["source_type"] = "document"
        # Add tactic from MITRE KB
        from analysis.network_mitre_map import TECHNIQUE_TO_TACTIC
        mitre_id = result.get("mitre_id", "N/A")
        result["tactic"] = TECHNIQUE_TO_TACTIC.get(mitre_id, "Unknown")
    return [result]


def _detect_network(file_path):
    """Run network IDS on a CSV of network flows."""
    from core.log_ingestion import ingest_csv
    from detection.network_detector import detect_from_dataframe
    import pandas as pd

    # Ingest the CSV
    features_df, meta_df = ingest_csv(file_path)

    # Read the raw CSV for passing to detector (needs original columns)
    raw_df = pd.read_csv(file_path, low_memory=False)
    raw_df.columns = raw_df.columns.str.strip()

    # Run batch detection
    results = detect_from_dataframe(raw_df)

    # Enrich with metadata
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for i, result in enumerate(results):
        result["timestamp"] = timestamp
        result["file_name"] = os.path.basename(file_path)
        result["file_path"] = str(file_path)
        # Add source IPs/ports if available
        if "srcip" in meta_df.columns:
            result["src_ip"] = str(meta_df.iloc[i].get("srcip", "N/A"))
        if "dstip" in meta_df.columns:
            result["dst_ip"] = str(meta_df.iloc[i].get("dstip", "N/A"))
        if "sport" in meta_df.columns:
            result["src_port"] = str(meta_df.iloc[i].get("sport", "N/A"))
        if "dsport" in meta_df.columns:
            result["dst_port"] = str(meta_df.iloc[i].get("dsport", "N/A"))

    return results
