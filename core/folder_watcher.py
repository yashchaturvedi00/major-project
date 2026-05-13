"""
Downloads folder watcher — monitors a directory for new files and auto-scans them
using the trained ML model for MITRE ATT&CK technique detection.
"""
import os
import sys
import time
import json
import threading
from pathlib import Path
from datetime import datetime

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


# ── Project path setup ───────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCAN_RESULTS_FILE = PROJECT_ROOT / "scan_results.json"

# Lazy-loaded globals
_model = None
_encoder = None
_attack_to_mitre = None
_mitre_kb = None


def _load_model():
    """Lazy-load all model artifacts."""
    global _model, _encoder, _attack_to_mitre, _mitre_kb
    import joblib

    if _model is None:
        _model = joblib.load(str(PROJECT_ROOT / "attack_model.pkl"))
        _encoder = joblib.load(str(PROJECT_ROOT / "label_encoder.pkl"))
        _attack_to_mitre = joblib.load(str(PROJECT_ROOT / "attack_to_mitre_map.pkl"))
        _mitre_kb = joblib.load(str(PROJECT_ROOT / "mitre_kb.pkl"))

    return _model, _encoder, _attack_to_mitre, _mitre_kb


def scan_file(file_path):
    """
    Scan a single file and return detection results.

    Returns:
        dict with keys: file_name, file_path, attack_type, confidence,
                        mitre_id, mitre_name, category, impact, timestamp, status
    """
    from detection.file_parser import extract_text, is_supported
    from detection.feature_extractor import extract_features_from_log

    file_name = os.path.basename(file_path)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Skip unsupported files
    if not is_supported(file_path):
        return {
            "file_name": file_name,
            "file_path": str(file_path),
            "status": "skipped",
            "reason": "Unsupported file type",
            "timestamp": timestamp,
        }

    # Extract text
    text = extract_text(file_path)
    if not text or len(text.strip()) < 10:
        return {
            "file_name": file_name,
            "file_path": str(file_path),
            "status": "skipped",
            "reason": "No readable text content",
            "timestamp": timestamp,
        }

    # Load model and predict
    model, encoder, attack_to_mitre, mitre_kb = _load_model()
    features = extract_features_from_log(text)

    prediction = model.predict(features)[0]
    probabilities = model.predict_proba(features)[0]
    confidence = round(float(probabilities.max()) * 100, 2)

    attack_type = encoder.inverse_transform([prediction])[0]

    # Map to MITRE technique
    mitre_id = attack_to_mitre.get(attack_type, "Unknown")
    mitre_info = mitre_kb.get(mitre_id, {})

    # Determine severity based on confidence
    if confidence >= 80:
        severity = "High"
    elif confidence >= 50:
        severity = "Medium"
    else:
        severity = "Low"

    return {
        "file_name": file_name,
        "file_path": str(file_path),
        "status": "scanned",
        "attack_type": attack_type,
        "confidence": confidence,
        "severity": severity,
        "mitre_id": mitre_id,
        "mitre_name": mitre_info.get("name", "Unknown"),
        "category": mitre_info.get("category", "Unknown"),
        "impact": mitre_info.get("impact", "Unknown"),
        "description": mitre_info.get("description", ""),
        "mitigation": mitre_info.get("mitigation", ""),
        "detection_method": mitre_info.get("detection_method", ""),
        "timestamp": timestamp,
    }


def _load_results():
    """Load existing scan results from JSON file."""
    if SCAN_RESULTS_FILE.exists():
        try:
            with open(SCAN_RESULTS_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return []
    return []


def _save_result(result):
    """Append a scan result to the JSON file (thread-safe)."""
    results = _load_results()
    results.insert(0, result)  # Newest first
    # Keep only last 100 results
    results = results[:100]
    with open(SCAN_RESULTS_FILE, "w") as f:
        json.dump(results, f, indent=2)


class DownloadHandler(FileSystemEventHandler):
    """Handles new file creation events in the watched folder."""

    def __init__(self):
        super().__init__()
        self._seen = set()

    def on_created(self, event):
        if event.is_directory:
            return

        file_path = event.src_path

        # Skip temp/partial download files
        basename = os.path.basename(file_path)
        if basename.startswith(".") or basename.endswith((".tmp", ".crdownload", ".part")):
            return

        # Avoid duplicate scans
        if file_path in self._seen:
            return
        self._seen.add(file_path)

        # Wait for file to finish writing
        self._wait_for_stable(file_path)

        # Scan in a separate thread to avoid blocking the observer
        threading.Thread(target=self._scan_and_save, args=(file_path,), daemon=True).start()

    def _wait_for_stable(self, file_path, timeout=30):
        """Wait until file size stabilizes (download complete)."""
        prev_size = -1
        waited = 0
        while waited < timeout:
            try:
                size = os.path.getsize(file_path)
                if size == prev_size and size > 0:
                    return
                prev_size = size
            except OSError:
                pass
            time.sleep(1)
            waited += 1

    def _scan_and_save(self, file_path):
        """Scan a file and save results."""
        try:
            print(f"[watcher] Scanning: {os.path.basename(file_path)}")
            result = scan_file(file_path)
            _save_result(result)

            if result["status"] == "scanned":
                print(f"[watcher] ⚠ Detected: {result['attack_type']} "
                      f"(MITRE: {result['mitre_id']}, Confidence: {result['confidence']}%)")
            else:
                print(f"[watcher] Skipped: {result.get('reason', 'unknown')}")
        except Exception as e:
            print(f"[watcher] Error scanning {file_path}: {e}")


def start_watcher(watch_folder=None, blocking=False):
    """
    Start watching a folder for new files.

    Args:
        watch_folder: Path to monitor (defaults to user's Downloads)
        blocking: If True, blocks the calling thread. If False, runs in background.
    """
    if watch_folder is None:
        watch_folder = str(Path.home() / "Downloads")

    print(f"[watcher] Monitoring: {watch_folder}")

    handler = DownloadHandler()
    observer = Observer()
    observer.schedule(handler, watch_folder, recursive=False)
    observer.start()

    if blocking:
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()
    else:
        return observer


if __name__ == "__main__":
    # Run standalone
    folder = sys.argv[1] if len(sys.argv) > 1 else None
    start_watcher(folder, blocking=True)
