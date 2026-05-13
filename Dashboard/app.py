# -------------------- FIX PROJECT PATH --------------------
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
os.chdir(PROJECT_ROOT)

# -------------------- IMPORTS --------------------
import streamlit as st
import pandas as pd
import json
import time
import threading
from datetime import datetime

# -------------------- PAGE CONFIG --------------------
st.set_page_config(
    page_title="MITRE ATT&CK Intelligent IDS",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# -------------------- CUSTOM CSS --------------------
st.markdown("""
<style>

@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

/* Dark theme overrides */
html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

.stApp {
    background: #09090b;
    background-image: 
        radial-gradient(circle at 15% 50%, rgba(59, 130, 246, 0.08), transparent 25%),
        radial-gradient(circle at 85% 30%, rgba(239, 68, 68, 0.05), transparent 25%);
}

/* Header styling */
.main-header {
    background: rgba(24, 24, 27, 0.6);
    backdrop-filter: blur(12px);
    -webkit-backdrop-filter: blur(12px);
    border-radius: 16px;
    padding: 32px;
    margin-bottom: 28px;
    border: 1px solid rgba(255, 255, 255, 0.05);
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
    text-align: center;
    animation: fadeInDown 0.8s ease-out;
}
.main-header h1 {
    color: #f8fafc;
    font-size: 2.4rem;
    margin-bottom: 10px;
    font-weight: 700;
    letter-spacing: -0.025em;
}
.main-header p {
    color: #94a3b8;
    font-size: 1.1rem;
    margin: 0;
    font-weight: 400;
}

/* Metric card styling */
.metric-card {
    background: rgba(30, 41, 59, 0.4);
    backdrop-filter: blur(8px);
    -webkit-backdrop-filter: blur(8px);
    border-radius: 12px;
    padding: 24px 20px;
    border: 1px solid rgba(255, 255, 255, 0.05);
    text-align: center;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    animation: fadeInUp 0.6s ease-out;
    animation-fill-mode: both;
}
.metric-card:hover {
    transform: translateY(-4px);
    border-color: rgba(59, 130, 246, 0.3);
    box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3), 0 8px 10px -6px rgba(0, 0, 0, 0.1);
}
.metric-value {
    font-size: 2.2rem;
    font-weight: 700;
    color: #f8fafc;
    line-height: 1.2;
}
.metric-label {
    font-size: 0.85rem;
    color: #94a3b8;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-top: 8px;
    font-weight: 600;
}

/* Delay animations for child elements */
div[data-testid="stHorizontalBlock"] > div:nth-child(1) .metric-card { animation-delay: 0.1s; }
div[data-testid="stHorizontalBlock"] > div:nth-child(2) .metric-card { animation-delay: 0.2s; }
div[data-testid="stHorizontalBlock"] > div:nth-child(3) .metric-card { animation-delay: 0.3s; }
div[data-testid="stHorizontalBlock"] > div:nth-child(4) .metric-card { animation-delay: 0.4s; }
div[data-testid="stHorizontalBlock"] > div:nth-child(5) .metric-card { animation-delay: 0.5s; }

/* Result card styling */
.result-card {
    background: rgba(30, 41, 59, 0.4);
    backdrop-filter: blur(8px);
    -webkit-backdrop-filter: blur(8px);
    border-radius: 12px;
    padding: 20px;
    margin-bottom: 16px;
    border-left: 4px solid;
    border-right: 1px solid rgba(255, 255, 255, 0.03);
    border-top: 1px solid rgba(255, 255, 255, 0.03);
    border-bottom: 1px solid rgba(255, 255, 255, 0.03);
    transition: transform 0.2s;
    animation: fadeInRight 0.5s ease-out;
    animation-fill-mode: both;
}
.result-card:hover {
    transform: translateX(4px);
    background: rgba(30, 41, 59, 0.6);
}
.result-card.high { border-left-color: #ef4444; }
.result-card.medium { border-left-color: #f59e0b; }
.result-card.low { border-left-color: #10b981; }
.result-card.skipped { border-left-color: #64748b; }
.result-card.none { border-left-color: #10b981; }

.severity-badge {
    display: inline-flex;
    align-items: center;
    padding: 4px 12px;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}
.severity-high { background: rgba(239, 68, 68, 0.15); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.3); }
.severity-medium { background: rgba(245, 158, 11, 0.15); color: #fcd34d; border: 1px solid rgba(245, 158, 11, 0.3); }
.severity-low { background: rgba(16, 185, 129, 0.15); color: #6ee7b7; border: 1px solid rgba(16, 185, 129, 0.3); }
.severity-skipped { background: rgba(100, 116, 139, 0.15); color: #cbd5e1; border: 1px solid rgba(100, 116, 139, 0.3); }
.severity-none { background: rgba(16, 185, 129, 0.15); color: #6ee7b7; border: 1px solid rgba(16, 185, 129, 0.3); }

/* Status indicator */
.status-live {
    display: inline-flex;
    align-items: center;
    gap: 10px;
    background: rgba(16, 185, 129, 0.1);
    border: 1px solid rgba(16, 185, 129, 0.2);
    border-radius: 9999px;
    padding: 8px 18px;
    color: #34d399;
    font-weight: 600;
    font-size: 0.9rem;
    box-shadow: 0 0 15px rgba(16, 185, 129, 0.1);
}
.status-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #34d399;
    box-shadow: 0 0 8px #34d399;
    animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
}
@keyframes pulse {
    0%, 100% { opacity: 1; transform: scale(1); }
    50% { opacity: 0.4; transform: scale(0.8); }
}

/* Info box */
.info-box {
    background: rgba(15, 23, 42, 0.6);
    backdrop-filter: blur(10px);
    -webkit-backdrop-filter: blur(10px);
    border-radius: 12px;
    padding: 24px;
    border: 1px solid rgba(56, 189, 248, 0.15);
    margin: 16px 0;
    animation: fadeInUp 0.7s ease-out;
}
.info-box h4 { 
    color: #38bdf8; 
    margin: 0 0 16px 0; 
    font-weight: 600;
    font-size: 1.1rem;
    display: flex;
    align-items: center;
    gap: 8px;
}
.info-box p { color: #cbd5e1; margin: 6px 0; font-size: 0.95rem; line-height: 1.5; }
.info-box p strong { color: #f8fafc; font-weight: 600; }

/* Kill chain stage */
.chain-stage {
    background: rgba(30, 41, 59, 0.4);
    backdrop-filter: blur(8px);
    border-radius: 12px;
    padding: 16px 12px;
    border: 1px solid rgba(255, 255, 255, 0.05);
    text-align: center;
    min-height: 130px;
    transition: all 0.3s ease;
    display: flex;
    flex-direction: column;
    justify-content: center;
}
.chain-stage.active {
    background: rgba(127, 29, 29, 0.2);
    border-color: rgba(239, 68, 68, 0.4);
    box-shadow: 0 0 20px rgba(239, 68, 68, 0.15), inset 0 0 10px rgba(239, 68, 68, 0.05);
    transform: translateY(-2px);
}
.chain-stage-label {
    font-size: 0.7rem;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 6px;
    font-weight: 600;
}
.chain-stage-icon {
    font-size: 1.8rem;
    margin-bottom: 8px;
    filter: drop-shadow(0 2px 4px rgba(0,0,0,0.2));
}

/* Animations */
@keyframes fadeInDown {
    from { opacity: 0; transform: translateY(-20px); }
    to { opacity: 1; transform: translateY(0); }
}
@keyframes fadeInUp {
    from { opacity: 0; transform: translateY(20px); }
    to { opacity: 1; transform: translateY(0); }
}
@keyframes fadeInRight {
    from { opacity: 0; transform: translateX(-20px); }
    to { opacity: 1; transform: translateX(0); }
}

/* Hide streamlit branding */
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}
header {visibility: hidden;}

/* Custom Scrollbar */
::-webkit-scrollbar {
    width: 8px;
    height: 8px;
}
::-webkit-scrollbar-track {
    background: rgba(15, 23, 42, 0.5);
}
::-webkit-scrollbar-thumb {
    background: rgba(71, 85, 105, 0.8);
    border-radius: 4px;
}
::-webkit-scrollbar-thumb:hover {
    background: rgba(100, 116, 139, 1);
}

/* Card grid fix */
div[data-testid="stHorizontalBlock"] > div {
    padding: 0 8px;
}

/* Training tab styles */
.training-terminal {
    background: #0c0c0c;
    border: 1px solid rgba(56, 189, 248, 0.2);
    border-radius: 10px;
    padding: 20px;
    font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
    font-size: 0.82rem;
    color: #4ade80;
    line-height: 1.7;
    overflow-x: auto;
    white-space: pre-wrap;
    max-height: 350px;
    overflow-y: auto;
    box-shadow: inset 0 2px 8px rgba(0,0,0,0.5);
}
.training-terminal .log-warn { color: #facc15; }
.training-terminal .log-crit { color: #f87171; font-weight: 700; }

.mitre-context-card {
    background: linear-gradient(135deg, rgba(30,41,59,0.6), rgba(15,23,42,0.8));
    border: 1px solid rgba(147,197,253,0.2);
    border-radius: 12px;
    padding: 20px;
    margin: 12px 0;
}
.mitre-context-card h4 { color: #93c5fd; margin: 0 0 12px 0; font-weight: 600; }
.mitre-context-card p { color: #cbd5e1; margin: 4px 0; font-size: 0.9rem; }
.mitre-context-card p strong { color: #f1f5f9; }

.feedback-correct {
    background: rgba(16,185,129,0.12);
    border: 1px solid rgba(16,185,129,0.4);
    border-left: 4px solid #10b981;
    border-radius: 12px;
    padding: 20px;
    margin: 12px 0;
    animation: fadeInUp 0.5s ease-out;
}
.feedback-incorrect {
    background: rgba(239,68,68,0.12);
    border: 1px solid rgba(239,68,68,0.4);
    border-left: 4px solid #ef4444;
    border-radius: 12px;
    padding: 20px;
    margin: 12px 0;
    animation: fadeInUp 0.5s ease-out;
}
.feedback-correct h3 { color: #34d399; margin: 0 0 8px 0; }
.feedback-incorrect h3 { color: #f87171; margin: 0 0 8px 0; }

.consequence-card {
    background: rgba(245,158,11,0.08);
    border: 1px solid rgba(245,158,11,0.25);
    border-radius: 10px;
    padding: 16px;
    margin: 10px 0;
}
.consequence-card h4 { color: #fbbf24; margin: 0 0 8px 0; font-size: 0.95rem; }
.consequence-card p { color: #cbd5e1; margin: 0; font-size: 0.9rem; }

.guidance-card {
    background: rgba(16,185,129,0.08);
    border: 1px solid rgba(16,185,129,0.25);
    border-radius: 10px;
    padding: 16px;
    margin: 10px 0;
}
.guidance-card h4 { color: #34d399; margin: 0 0 8px 0; font-size: 0.95rem; }
.guidance-card p { color: #cbd5e1; margin: 0; font-size: 0.9rem; white-space: pre-line; }

.score-sidebar-card {
    background: rgba(30,41,59,0.5);
    border: 1px solid rgba(255,255,255,0.06);
    border-radius: 10px;
    padding: 14px;
    margin: 8px 0;
    text-align: center;
}
.score-sidebar-card .score-val { font-size: 1.6rem; font-weight: 700; color: #f8fafc; }
.score-sidebar-card .score-lbl { font-size: 0.75rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 4px; }

</style>
""", unsafe_allow_html=True)


# -------------------- HEADER --------------------
st.markdown("""
<div class="main-header">
    <h1>🛡️ MITRE ATT&CK Intelligent IDS</h1>
    <p>Multi-vector intrusion detection with kill chain reconstruction</p>
</div>
""", unsafe_allow_html=True)


# -------------------- TABS --------------------
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "📄 Document Scanner",
    "🌐 Network IDS",
    "⛓️ Attack Chain",
    "🗺️ MITRE Heatmap",
    "🎯 Response Training",
])

SCAN_RESULTS_FILE = PROJECT_ROOT / "scan_results.json"


def load_scan_results():
    """Load scan results from JSON file."""
    if SCAN_RESULTS_FILE.exists():
        try:
            with open(SCAN_RESULTS_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return []
    return []


# =====================================
# TAB 1: DOCUMENT SCANNER
# =====================================
with tab1:
    st.sidebar.markdown("## ⚙️ Settings")
    mode = st.sidebar.radio(
        "Document Mode",
        ["🔴 Live Monitor", "📁 Manual Upload"],
        index=0,
        help="Live Monitor watches your Downloads folder. Manual Upload lets you analyze any file."
    )

    # ── LIVE MONITOR ──
    if mode == "🔴 Live Monitor":
        from core.folder_watcher import start_watcher, SCAN_RESULTS_FILE

        watch_folder = st.sidebar.text_input(
            "📂 Monitored Folder",
            value=str(Path.home() / "Downloads"),
            help="Path to the folder to monitor for new files"
        )

        if "watcher_started" not in st.session_state:
            st.session_state.watcher_started = False

        if st.sidebar.button("▶️ Start Monitoring", use_container_width=True, type="primary"):
            if not st.session_state.watcher_started:
                observer = start_watcher(watch_folder, blocking=False)
                st.session_state.watcher_started = True
                st.session_state.watcher_observer = observer

        if st.session_state.watcher_started:
            st.sidebar.markdown("""
            <div class="status-live">
                <div class="status-dot"></div>
                Monitoring Active
            </div>
            """, unsafe_allow_html=True)
            st.sidebar.caption(f"Watching: `{watch_folder}`")

            if st.sidebar.button("⏹️ Stop Monitoring", use_container_width=True):
                if hasattr(st.session_state, "watcher_observer"):
                    st.session_state.watcher_observer.stop()
                st.session_state.watcher_started = False
                st.rerun()
        else:
            st.info("👆 Click **Start Monitoring** in the sidebar to begin watching your Downloads folder.")

        refresh_rate = st.sidebar.slider("Refresh interval (seconds)", 3, 30, 5)

        results = load_scan_results()

        if results:
            scanned = [r for r in results if r.get("status") == "scanned"]
            skipped = [r for r in results if r.get("status") == "skipped"]
            high_sev = [r for r in scanned if r.get("severity") == "High"]

            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-value">{len(results)}</div>
                    <div class="metric-label">Total Files</div>
                </div>""", unsafe_allow_html=True)
            with col2:
                st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-value">{len(scanned)}</div>
                    <div class="metric-label">Analyzed</div>
                </div>""", unsafe_allow_html=True)
            with col3:
                st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-value" style="color: #ef4444;">{len(high_sev)}</div>
                    <div class="metric-label">High Severity</div>
                </div>""", unsafe_allow_html=True)
            with col4:
                avg_confidence = sum(r.get("confidence", 0) for r in scanned) / max(len(scanned), 1)
                st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-value">{avg_confidence:.1f}%</div>
                    <div class="metric-label">Avg Confidence</div>
                </div>""", unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown("### 📋 Scan Results")

            for result in results[:20]:
                status = result.get("status", "unknown")
                severity = result.get("severity", "low").lower() if status == "scanned" else "skipped"
                severity_class = f"severity-{severity}"

                if status == "scanned":
                    st.markdown(f"""
                    <div class="result-card {severity}">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                            <div>
                                <strong style="color: #f1f5f9; font-size: 1.05rem;">📄 {result.get('file_name', 'Unknown')}</strong>
                            </div>
                            <div>
                                <span class="severity-badge {severity_class}">{result.get('severity', 'Unknown')}</span>
                            </div>
                        </div>
                        <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 8px;">
                            <p style="color: #94a3b8; margin: 2px 0;">⚔️ Attack: <strong style="color: #e2e8f0;">{result.get('attack_type', 'N/A')}</strong></p>
                            <p style="color: #94a3b8; margin: 2px 0;">🎯 MITRE: <strong style="color: #93c5fd;">{result.get('mitre_id', 'N/A')}</strong></p>
                            <p style="color: #94a3b8; margin: 2px 0;">📊 Confidence: <strong style="color: #e2e8f0;">{result.get('confidence', 0)}%</strong></p>
                        </div>
                        <p style="color: #64748b; font-size: 0.8rem; margin-top: 8px;">🕐 {result.get('timestamp', '')}</p>
                    </div>
                    """, unsafe_allow_html=True)

                    with st.expander(f"🔍 Details — {result.get('file_name', '')}"):
                        det_col1, det_col2 = st.columns(2)
                        with det_col1:
                            st.markdown(f"""
                            <div class="info-box">
                                <h4>🎯 Threat Intelligence</h4>
                                <p><strong>Attack Type:</strong> {result.get('attack_type', 'N/A')}</p>
                                <p><strong>MITRE Technique:</strong> {result.get('mitre_id', 'N/A')} — {result.get('mitre_name', 'N/A')}</p>
                                <p><strong>Category:</strong> {result.get('category', 'N/A')}</p>
                                <p><strong>Impact:</strong> {result.get('impact', 'N/A')}</p>
                            </div>
                            """, unsafe_allow_html=True)
                        with det_col2:
                            st.markdown(f"""
                            <div class="info-box">
                                <h4>🛡️ Response</h4>
                                <p><strong>Mitigation:</strong> {result.get('mitigation', 'N/A')}</p>
                                <p><strong>Detection Method:</strong> {result.get('detection_method', 'N/A')}</p>
                                <p><strong>File Path:</strong> {result.get('file_path', 'N/A')}</p>
                            </div>
                            """, unsafe_allow_html=True)
                else:
                    st.markdown(f"""
                    <div class="result-card skipped">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <strong style="color: #94a3b8;">⏭️ {result.get('file_name', 'Unknown')}</strong>
                            <span class="severity-badge severity-skipped">Skipped</span>
                        </div>
                        <p style="color: #64748b; margin: 4px 0; font-size: 0.9rem;">Reason: {result.get('reason', 'N/A')} — {result.get('timestamp', '')}</p>
                    </div>
                    """, unsafe_allow_html=True)

        else:
            if st.session_state.watcher_started:
                st.markdown("""
                <div class="info-box" style="text-align: center;">
                    <h4>👀 Waiting for new files...</h4>
                    <p>Download any file and it will be automatically scanned.</p>
                    <p>Supported formats: TXT, LOG, CSV, PDF, DOCX</p>
                </div>
                """, unsafe_allow_html=True)

        if st.session_state.get("watcher_started"):
            time.sleep(refresh_rate)
            st.rerun()

    # ── MANUAL UPLOAD ──
    elif mode == "📁 Manual Upload":
        from core.folder_watcher import scan_file
        from detection.file_parser import extract_text, SUPPORTED_EXTENSIONS
        from detection.feature_extractor import extract_features_from_log
        import joblib
        import tempfile
        import numpy as np

        st.markdown("### 📤 Upload a Document for Analysis")
        st.caption("Supported formats: TXT, LOG, CSV, PDF, DOCX")

        uploaded_file = st.file_uploader(
            "Choose a file",
            type=["txt", "log", "csv", "pdf", "docx"],
            help="Upload any document to check for MITRE ATT&CK techniques",
            key="doc_upload",
        )

        if uploaded_file is not None:
            with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(uploaded_file.name)[1]) as tmp:
                tmp.write(uploaded_file.getvalue())
                tmp_path = tmp.name

            st.markdown(f"**File:** `{uploaded_file.name}` ({uploaded_file.size:,} bytes)")

            if st.button("🔍 Analyze File", use_container_width=True, type="primary"):
                with st.spinner("Analyzing document..."):
                    start_time = time.time()
                    result = scan_file(tmp_path)
                    elapsed = round(time.time() - start_time, 3)

                    # Store in session state for attack chain
                    if "all_detections" not in st.session_state:
                        st.session_state.all_detections = []
                    if result.get("status") == "scanned":
                        result["source_type"] = "document"
                        st.session_state.all_detections.append(result)

                if result.get("status") == "scanned":
                    severity = result.get("severity", "Low")
                    sev_color = {"High": "#ef4444", "Medium": "#f59e0b", "Low": "#22c55e"}.get(severity, "#94a3b8")
                    st.success(f"Analysis complete in {elapsed}s")

                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        st.markdown(f"""
                        <div class="metric-card">
                            <div class="metric-value" style="font-size: 1.3rem;">{result.get('attack_type', 'N/A')}</div>
                            <div class="metric-label">Attack Type</div>
                        </div>""", unsafe_allow_html=True)
                    with col2:
                        st.markdown(f"""
                        <div class="metric-card">
                            <div class="metric-value" style="color: #93c5fd;">{result.get('mitre_id', 'N/A')}</div>
                            <div class="metric-label">MITRE Technique</div>
                        </div>""", unsafe_allow_html=True)
                    with col3:
                        st.markdown(f"""
                        <div class="metric-card">
                            <div class="metric-value">{result.get('confidence', 0)}%</div>
                            <div class="metric-label">Confidence</div>
                        </div>""", unsafe_allow_html=True)
                    with col4:
                        st.markdown(f"""
                        <div class="metric-card">
                            <div class="metric-value" style="color: {sev_color};">{severity}</div>
                            <div class="metric-label">Severity</div>
                        </div>""", unsafe_allow_html=True)

                    st.markdown("<br>", unsafe_allow_html=True)

                    det_col1, det_col2 = st.columns(2)
                    with det_col1:
                        st.markdown(f"""
                        <div class="info-box">
                            <h4>🎯 Threat Intelligence</h4>
                            <p><strong>Attack Type:</strong> {result.get('attack_type', 'N/A')}</p>
                            <p><strong>MITRE Technique:</strong> {result.get('mitre_id', 'N/A')} — {result.get('mitre_name', 'N/A')}</p>
                            <p><strong>Category:</strong> {result.get('category', 'N/A')}</p>
                            <p><strong>Impact:</strong> {result.get('impact', 'N/A')}</p>
                        </div>
                        """, unsafe_allow_html=True)
                    with det_col2:
                        st.markdown(f"""
                        <div class="info-box">
                            <h4>🛡️ Recommended Response</h4>
                            <p><strong>Description:</strong> {result.get('description', 'N/A')[:200]}</p>
                            <p><strong>Mitigation:</strong> {result.get('mitigation', 'N/A')[:200]}</p>
                            <p><strong>Detection Method:</strong> {result.get('detection_method', 'N/A')[:200]}</p>
                        </div>
                        """, unsafe_allow_html=True)
                else:
                    st.warning(f"Could not analyze: {result.get('reason', 'Unknown error')}")

            try:
                os.unlink(tmp_path)
            except Exception:
                pass

        else:
            st.markdown("""
            <div class="info-box" style="text-align: center;">
                <h4>📤 Drop a file above to get started</h4>
                <p>The scanner will analyze the document content and identify potential MITRE ATT&CK techniques.</p>
                <p style="font-size: 0.85rem; color: #64748b;">Supported: TXT, LOG, CSV, PDF, DOCX</p>
            </div>
            """, unsafe_allow_html=True)


# =====================================
# TAB 2: NETWORK IDS
# =====================================
with tab2:
    st.markdown("### 🌐 Network Traffic Analysis")
    st.caption("Upload a UNSW-NB15 format CSV to analyze network flows for attacks")

    # Check if network model exists
    network_model_path = PROJECT_ROOT / "network_model.pkl"
    if not network_model_path.exists():
        st.warning(
            "⚠️ Network IDS model not trained yet. Run `python scripts/train_network_model.py` first.\n\n"
            "**Steps:**\n"
            "1. Download UNSW-NB15 dataset from [Kaggle](https://www.kaggle.com/mrwellsdavid/unsw-nb15)\n"
            "2. Place `UNSW_NB15_training-set.csv` and `UNSW_NB15_testing-set.csv` in `Dataset/network/`\n"
            "3. Run: `python scripts/train_network_model.py`"
        )
    else:
        uploaded_csv = st.file_uploader(
            "Upload network flow CSV",
            type=["csv"],
            help="UNSW-NB15 format CSV with network flow features",
            key="network_upload",
        )

        if uploaded_csv is not None:
            import tempfile
            with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as tmp:
                tmp.write(uploaded_csv.getvalue())
                tmp_path = tmp.name

            st.markdown(f"**File:** `{uploaded_csv.name}` ({uploaded_csv.size:,} bytes)")

            if st.button("🚀 Analyze Network Traffic", use_container_width=True, type="primary"):
                with st.spinner("Analyzing network flows..."):
                    from detection.network_detector import detect_from_dataframe
                    import pandas as pd

                    df = pd.read_csv(tmp_path, low_memory=False)
                    df.columns = df.columns.str.strip()

                    start_time = time.time()
                    results = detect_from_dataframe(df)
                    elapsed = round(time.time() - start_time, 3)

                    # Store in session for attack chain
                    if "all_detections" not in st.session_state:
                        st.session_state.all_detections = []
                    for r in results:
                        if r["attack_type"] != "Normal":
                            r["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            st.session_state.all_detections.append(r)

                st.success(f"Analyzed {len(results):,} flows in {elapsed}s")

                # Summary metrics
                attacks = [r for r in results if r["attack_type"] != "Normal"]
                high_sev = [r for r in attacks if r.get("severity") == "High"]
                unique_types = set(r["attack_type"] for r in attacks)

                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.markdown(f"""
                    <div class="metric-card">
                        <div class="metric-value">{len(results):,}</div>
                        <div class="metric-label">Total Flows</div>
                    </div>""", unsafe_allow_html=True)
                with col2:
                    st.markdown(f"""
                    <div class="metric-card">
                        <div class="metric-value" style="color: #ef4444;">{len(attacks):,}</div>
                        <div class="metric-label">Attacks Detected</div>
                    </div>""", unsafe_allow_html=True)
                with col3:
                    st.markdown(f"""
                    <div class="metric-card">
                        <div class="metric-value" style="color: #f59e0b;">{len(unique_types)}</div>
                        <div class="metric-label">Attack Types</div>
                    </div>""", unsafe_allow_html=True)
                with col4:
                    st.markdown(f"""
                    <div class="metric-card">
                        <div class="metric-value" style="color: #ef4444;">{len(high_sev):,}</div>
                        <div class="metric-label">High Severity</div>
                    </div>""", unsafe_allow_html=True)

                st.markdown("<br>", unsafe_allow_html=True)

                # Results table
                results_df = pd.DataFrame(results)
                st.markdown("### 📊 Detection Results")

                # Attack distribution charts
                chart_col1, chart_col2 = st.columns(2)
                with chart_col1:
                    st.markdown("**Attack Type Distribution**")
                    attack_counts = results_df["attack_type"].value_counts()
                    st.bar_chart(attack_counts)

                with chart_col2:
                    st.markdown("**Severity Distribution**")
                    severity_counts = results_df["severity"].value_counts()
                    st.bar_chart(severity_counts)

                # Detailed table
                display_cols = ["attack_type", "confidence", "severity", "mitre_id", "tactic"]
                st.dataframe(
                    results_df[display_cols],
                    use_container_width=True,
                    height=400,
                )

                # MITRE technique summary
                st.markdown("### 🎯 MITRE Techniques Detected")
                mitre_summary = results_df[results_df["attack_type"] != "Normal"].groupby(
                    ["mitre_id", "attack_type", "tactic"]
                ).agg(
                    count=("confidence", "size"),
                    avg_confidence=("confidence", "mean"),
                ).reset_index()
                mitre_summary["avg_confidence"] = mitre_summary["avg_confidence"].round(1)
                st.dataframe(mitre_summary, use_container_width=True)

            try:
                os.unlink(tmp_path)
            except Exception:
                pass

        else:
            st.markdown("""
            <div class="info-box" style="text-align: center;">
                <h4>🌐 Upload Network Flow Data</h4>
                <p>Upload a CSV file with UNSW-NB15 format network flow records.</p>
                <p style="font-size: 0.85rem; color: #64748b;">The model will classify each flow as Normal or one of 9 attack categories.</p>
            </div>
            """, unsafe_allow_html=True)


# =====================================
# TAB 3: ATTACK CHAIN
# =====================================
with tab3:
    from analysis.attack_chain import AttackChainBuilder, TACTIC_ORDER

    st.markdown("### ⛓️ Attack Chain Reconstruction")
    st.caption("Visualizes how detected attacks map to the MITRE ATT&CK kill chain")

    # Get all detections from session state
    all_detections = st.session_state.get("all_detections", [])

    if not all_detections:
        st.markdown("""
        <div class="info-box" style="text-align: center;">
            <h4>⛓️ No detections yet</h4>
            <p>Analyze documents in the <strong>Document Scanner</strong> tab or network flows in the <strong>Network IDS</strong> tab.</p>
            <p>Detected attacks will appear here as a kill chain progression.</p>
        </div>
        """, unsafe_allow_html=True)
    else:
        # Build chain
        builder = AttackChainBuilder()
        builder.add_detections(all_detections)
        stats = builder.get_stats()
        chain_by_tactic = builder.get_chain_by_tactic()

        # Stats bar
        col1, col2, col3, col4, col5 = st.columns(5)
        with col1:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-value">{stats['total_detections']}</div>
                <div class="metric-label">Total Alerts</div>
            </div>""", unsafe_allow_html=True)
        with col2:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-value">{stats['active_tactics']}</div>
                <div class="metric-label">Active Tactics</div>
            </div>""", unsafe_allow_html=True)
        with col3:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-value">{stats['chain_coverage']}%</div>
                <div class="metric-label">Chain Coverage</div>
            </div>""", unsafe_allow_html=True)
        with col4:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-value">📄 {stats['document_detections']}</div>
                <div class="metric-label">Doc Alerts</div>
            </div>""", unsafe_allow_html=True)
        with col5:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-value">🌐 {stats['network_detections']}</div>
                <div class="metric-label">Net Alerts</div>
            </div>""", unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # Summary narrative
        summary = builder.get_chain_summary()
        st.markdown(f"""
        <div class="info-box">
            <h4>📜 Attack Narrative</h4>
            <p>{summary}</p>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # Kill chain visualization — show all 14 tactics as stages
        st.markdown("### 🔗 Kill Chain Progression")

        active_tactics = builder.get_active_tactics()

        # Show in two rows of 7
        for row_start in [0, 7]:
            cols = st.columns(7)
            for i, col in enumerate(cols):
                idx = row_start + i
                if idx < len(TACTIC_ORDER):
                    tactic_name, stage, icon = TACTIC_ORDER[idx]
                    is_active = tactic_name in active_tactics
                    active_class = "active" if is_active else ""
                    count = len(chain_by_tactic.get(tactic_name, []))

                    with col:
                        if is_active:
                            st.markdown(f"""
                            <div class="chain-stage active">
                                <div class="chain-stage-icon">{icon}</div>
                                <div class="chain-stage-label">Stage {stage}</div>
                                <strong style="color: #ef4444; font-size: 0.85rem;">{tactic_name}</strong>
                                <br><span style="color: #f59e0b; font-size: 0.8rem;">{count} alert{'s' if count != 1 else ''}</span>
                            </div>
                            """, unsafe_allow_html=True)
                        else:
                            st.markdown(f"""
                            <div class="chain-stage">
                                <div class="chain-stage-icon" style="opacity: 0.3;">{icon}</div>
                                <div class="chain-stage-label">Stage {stage}</div>
                                <span style="color: #475569; font-size: 0.85rem;">{tactic_name}</span>
                            </div>
                            """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # Detailed detection list per tactic
        st.markdown("### 📋 Detections by Tactic")
        for tactic_name, detections in chain_by_tactic.items():
            icon = builder.detections[0]["tactic_icon"] if detections else "❓"
            for det in detections:
                if det["tactic"] == tactic_name:
                    icon = det["tactic_icon"]
                    break

            with st.expander(f"{icon} {tactic_name} — {len(detections)} detection{'s' if len(detections) != 1 else ''}"):
                for det in detections:
                    severity = det.get("severity", "Low").lower()
                    source_icon = "📄" if det.get("source_type") == "document" else "🌐"
                    st.markdown(f"""
                    <div class="result-card {severity}">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <strong style="color: #f1f5f9;">{source_icon} {det.get('attack_type', 'N/A')}</strong>
                            <span class="severity-badge severity-{severity}">{det.get('severity', 'Unknown')}</span>
                        </div>
                        <p style="color: #94a3b8; margin: 4px 0;">MITRE: <strong style="color: #93c5fd;">{det.get('mitre_id', 'N/A')}</strong> | Confidence: {det.get('confidence', 0)}% | Source: {det.get('source_type', 'N/A')}</p>
                    </div>
                    """, unsafe_allow_html=True)

        # Clear button
        if st.button("🗑️ Clear All Detections", use_container_width=True):
            st.session_state.all_detections = []
            st.rerun()


# =====================================
# TAB 4: MITRE HEATMAP
# =====================================
with tab4:
    from analysis.mitre_knowledge_base import MITRE_KB
    from analysis.attack_chain import TECHNIQUE_TO_TACTIC

    st.markdown("### 🗺️ MITRE ATT&CK Technique Coverage")
    st.caption("Shows which MITRE techniques your IDS can detect and current alert counts")

    all_detections = st.session_state.get("all_detections", [])

    # Count detections per technique
    detection_counts = {}
    for det in all_detections:
        mid = det.get("mitre_id", "N/A")
        if mid != "N/A":
            detection_counts[mid] = detection_counts.get(mid, 0) + 1

    # Build heatmap data
    tactics_group = {}
    for tech_id, info in MITRE_KB.items():
        tactic = info.get("tactic", "Unknown")
        if tactic not in tactics_group:
            tactics_group[tactic] = []
        tactics_group[tactic].append({
            "technique_id": tech_id,
            "name": info.get("name", "Unknown"),
            "count": detection_counts.get(tech_id, 0),
            "description": info.get("description", ""),
            "impact": info.get("impact", ""),
        })

    # Display as a grid grouped by tactic
    for tactic, techniques in tactics_group.items():
        st.markdown(f"#### 📌 {tactic}")

        cols = st.columns(min(len(techniques), 4))
        for i, tech in enumerate(techniques):
            count = tech["count"]
            if count > 0:
                bg_color = "rgba(239, 68, 68, 0.2)"
                border_color = "rgba(239, 68, 68, 0.5)"
                count_color = "#ef4444"
            else:
                bg_color = "rgba(100, 116, 139, 0.1)"
                border_color = "rgba(100, 116, 139, 0.3)"
                count_color = "#64748b"

            with cols[i % len(cols)]:
                st.markdown(f"""
                <div style="background: {bg_color}; border: 1px solid {border_color};
                     border-radius: 10px; padding: 14px; margin-bottom: 10px; min-height: 100px;">
                    <div style="color: #93c5fd; font-weight: 700; font-size: 1rem;">{tech['technique_id']}</div>
                    <div style="color: #e2e8f0; font-size: 0.85rem; margin: 4px 0;">{tech['name']}</div>
                    <div style="color: {count_color}; font-weight: 700; font-size: 1.3rem; margin-top: 8px;">
                        {count} alert{'s' if count != 1 else ''}
                    </div>
                </div>
                """, unsafe_allow_html=True)

        st.markdown("---")

    # Full technique details table
    st.markdown("### 📚 Full Technique Reference")
    kb_data = []
    for tech_id, info in MITRE_KB.items():
        kb_data.append({
            "MITRE ID": tech_id,
            "Name": info.get("name", ""),
            "Tactic": info.get("tactic", ""),
            "Impact": info.get("impact", ""),
            "Alerts": detection_counts.get(tech_id, 0),
        })

    kb_df = pd.DataFrame(kb_data)
    st.dataframe(kb_df, use_container_width=True, height=400)


# =====================================
# TAB 5: RESPONSE TRAINING
# =====================================
with tab5:
    from training.scenario_engine import get_all_scenarios, get_random_scenario, generate_scenario_from_detection
    from training.user_evaluation import evaluate_response
    from training.scoring_system import init_scoring, record_attempt, get_score_summary, get_performance_by_tactic, reset_scores
    from training.adaptive_learning import get_difficulty_label, get_learning_insights, recommend_next_scenario

    init_scoring()

    st.markdown("### 🎯 Interactive Attack Response Training")
    st.caption("Practice incident response with realistic attack scenarios — get scored and receive expert feedback")

    all_scenarios = get_all_scenarios()
    score_summary = get_score_summary()
    perf_by_tactic = get_performance_by_tactic()

    # ── Sidebar Scoreboard ──
    st.sidebar.markdown("---")
    st.sidebar.markdown("## 🏆 Training Score")
    diff_label = get_difficulty_label(score_summary)
    diff_colors = {"Beginner": "#60a5fa", "Intermediate": "#fbbf24", "Expert": "#34d399"}
    st.sidebar.markdown(f'<div style="text-align:center;margin-bottom:8px;"><span style="background:rgba(99,102,241,0.15);border:1px solid rgba(99,102,241,0.3);border-radius:9999px;padding:4px 14px;color:{diff_colors.get(diff_label,"#94a3b8")};font-weight:700;font-size:0.85rem;">{diff_label}</span></div>', unsafe_allow_html=True)

    sb_c1, sb_c2, sb_c3 = st.sidebar.columns(3)
    with sb_c1:
        st.markdown(f'<div class="score-sidebar-card"><div class="score-val">{score_summary["total_points"]}</div><div class="score-lbl">Points</div></div>', unsafe_allow_html=True)
    with sb_c2:
        st.markdown(f'<div class="score-sidebar-card"><div class="score-val">{score_summary["accuracy"]}%</div><div class="score-lbl">Accuracy</div></div>', unsafe_allow_html=True)
    with sb_c3:
        st.markdown(f'<div class="score-sidebar-card"><div class="score-val">{score_summary["total_correct"]}/{score_summary["total_attempts"]}</div><div class="score-lbl">Correct</div></div>', unsafe_allow_html=True)

    if perf_by_tactic:
        st.sidebar.markdown("**Performance by Tactic:**")
        for tactic, stats in perf_by_tactic.items():
            st.sidebar.progress(stats["accuracy"] / 100, text=f"{tactic}: {stats['accuracy']}%")

    insights = get_learning_insights(score_summary, perf_by_tactic)
    for insight in insights:
        st.sidebar.markdown(f"<p style='font-size:0.85rem;color:#cbd5e1;margin:4px 0;'>{insight}</p>", unsafe_allow_html=True)

    if score_summary["total_attempts"] > 0:
        if st.sidebar.button("🔄 Reset Scores", use_container_width=True):
            reset_scores()
            st.rerun()

    # ── Scenario Selection ──
    train_mode = st.radio("Training Mode", ["📝 Practice Mode", "🔴 Detection-Based"], horizontal=True, label_visibility="collapsed")

    current_scenario = None

    if train_mode == "📝 Practice Mode":
        sel_col1, sel_col2 = st.columns([3, 1])
        with sel_col1:
            scenario_names = [f"{s['mitre_id']} — {s['attack_type']} ({s['severity']})" for s in all_scenarios]
            selected_idx = st.selectbox("Select Scenario", range(len(scenario_names)), format_func=lambda i: scenario_names[i])
            current_scenario = all_scenarios[selected_idx]
        with sel_col2:
            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("🎲 Random", use_container_width=True):
                import random as _rnd
                st.session_state["training_random_idx"] = _rnd.randint(0, len(all_scenarios) - 1)
                st.rerun()
            if "training_random_idx" in st.session_state:
                current_scenario = all_scenarios[st.session_state["training_random_idx"]]
    else:
        det_list = st.session_state.get("all_detections", [])
        if det_list:
            latest = det_list[-1]
            current_scenario = generate_scenario_from_detection(latest)
            st.info(f"Scenario generated from latest detection: **{latest.get('attack_type', 'Unknown')}** ({latest.get('mitre_id', 'N/A')})")
        else:
            st.warning("No detections available. Analyze a document or network flow first, or use Practice Mode.")
            current_scenario = all_scenarios[0]

    if current_scenario:
        sc = current_scenario
        scenario_key = f"training_{sc['scenario_id']}"

        # ── Scenario Header ──
        sev_colors = {"High": "#ef4444", "Medium": "#f59e0b", "Low": "#22c55e"}
        sev_c = sev_colors.get(sc["severity"], "#94a3b8")

        hdr_c1, hdr_c2, hdr_c3, hdr_c4 = st.columns(4)
        with hdr_c1:
            st.markdown(f'<div class="metric-card"><div class="metric-value" style="font-size:1.2rem;">{sc["attack_type"]}</div><div class="metric-label">Attack Type</div></div>', unsafe_allow_html=True)
        with hdr_c2:
            st.markdown(f'<div class="metric-card"><div class="metric-value" style="color:#93c5fd;">{sc["mitre_id"]}</div><div class="metric-label">MITRE Technique</div></div>', unsafe_allow_html=True)
        with hdr_c3:
            st.markdown(f'<div class="metric-card"><div class="metric-value">{sc["tactic"]}</div><div class="metric-label">Kill Chain Stage {sc["kill_chain_stage"]}</div></div>', unsafe_allow_html=True)
        with hdr_c4:
            st.markdown(f'<div class="metric-card"><div class="metric-value" style="color:{sev_c};">{sc["severity"]}</div><div class="metric-label">Severity</div></div>', unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # ── Attack Description ──
        st.markdown(f"""
        <div class="info-box">
            <h4>⚠️ Attack Scenario</h4>
            <p>{sc['description']}</p>
        </div>
        """, unsafe_allow_html=True)

        # ── MITRE Context ──
        st.markdown(f"""
        <div class="mitre-context-card">
            <h4>🎯 MITRE ATT&CK Context</h4>
            <p><strong>Technique:</strong> {sc['mitre_id']} — {sc['mitre_name']}</p>
            <p><strong>Tactic:</strong> {sc['tactic']} (Kill Chain Stage {sc['kill_chain_stage']} of 14)</p>
            <p><strong>Severity:</strong> <span style="color:{sev_c};font-weight:700;">{sc['severity']}</span></p>
        </div>
        """, unsafe_allow_html=True)

        # ── Realistic Logs ──
        st.markdown("#### 📟 System Logs")
        log_lines = sc["realistic_logs"].strip().split("\n")
        formatted_logs = ""
        for line in log_lines:
            if "[WARNING]" in line or "WARNING" in line:
                formatted_logs += f'<span class="log-warn">{line}</span>\n'
            elif "[CRITICAL]" in line or "CRITICAL" in line:
                formatted_logs += f'<span class="log-crit">{line}</span>\n'
            else:
                formatted_logs += f"{line}\n"
        st.markdown(f'<div class="training-terminal">{formatted_logs}</div>', unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # ── Response Options ──
        st.markdown("#### 🤔 How would you respond?")
        option_texts = [f"{opt['id']}. {opt['text']}" for opt in sc["options"]]
        selected = st.radio("Select your response:", option_texts, key=f"{scenario_key}_radio", label_visibility="collapsed")
        selected_id = selected.split(".")[0] if selected else None

        submitted = st.button("✅ Submit Response", use_container_width=True, type="primary", key=f"{scenario_key}_submit")

        # ── Evaluation ──
        if submitted and selected_id:
            result = evaluate_response(sc, selected_id)

            if "error" not in result:
                record_attempt(sc["scenario_id"], result["is_correct"], sc["severity"], sc["tactic"])

                if result["is_correct"]:
                    st.markdown(f"""
                    <div class="feedback-correct">
                        <h3>✅ Correct!</h3>
                        <p style="color:#d1fae5;font-size:0.95rem;">{result['explanation']}</p>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.markdown(f"""
                    <div class="feedback-incorrect">
                        <h3>❌ Incorrect</h3>
                        <p style="color:#fecaca;font-size:0.95rem;">{result['explanation']}</p>
                        <p style="color:#94a3b8;margin-top:10px;">✅ <strong style="color:#34d399;">Correct answer:</strong> <span style="color:#e2e8f0;">{result['correct_option_text']}</span></p>
                    </div>
                    """, unsafe_allow_html=True)

                ev_c1, ev_c2 = st.columns(2)
                with ev_c1:
                    st.markdown(f"""
                    <div class="consequence-card">
                        <h4>⚡ Real-World Consequences</h4>
                        <p>{result['consequences']}</p>
                    </div>
                    """, unsafe_allow_html=True)
                with ev_c2:
                    st.markdown(f"""
                    <div class="guidance-card">
                        <h4>🛡️ Mitigation Guidance</h4>
                        <p>{result['mitigation_guidance']}</p>
                    </div>
                    """, unsafe_allow_html=True)

                if result.get("real_world_example"):
                    st.markdown(f"""
                    <div class="info-box">
                        <h4>🌍 Real-World Reference</h4>
                        <p>{result['real_world_example']}</p>
                    </div>
                    """, unsafe_allow_html=True)

                st.markdown("<br>", unsafe_allow_html=True)

                rec = recommend_next_scenario(all_scenarios, get_performance_by_tactic())
                if rec:
                    st.info(f"📚 **Recommended next:** {rec['mitre_id']} — {rec['attack_type']} ({rec['tactic']})")


# -------------------- FOOTER --------------------
st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #64748b; font-size: 0.85rem;">
    <p>🛡️ MITRE ATT&CK Intelligent IDS — Multi-Vector Intrusion Detection</p>
    <p>Document Scanner: TF-IDF + LinearSVC | Network IDS: RandomForest | UNSW-NB15 + Attack Dataset</p>
</div>
""", unsafe_allow_html=True)
