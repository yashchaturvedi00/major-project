<<<<<<< HEAD
# 🛡️ MITRE ATT&CK Intelligent IDS

> A multi-vector Intrusion Detection System that combines **document content analysis** and **network traffic classification** with **MITRE ATT&CK kill chain reconstruction**.

---

## 🎯 What Makes This Different

Unlike traditional IDS tools (Snort, Suricata, Wazuh) that focus on a single detection vector, this system:

1. **Multi-Vector Detection** — Analyzes both document content AND network flow data
2. **MITRE ATT&CK Mapping** — Every detection is classified into a specific MITRE technique
3. **Kill Chain Reconstruction** — Links individual alerts into an attack progression narrative
4. **Automated Threat Intelligence** — Provides impact, mitigation, and detection guidance for every alert

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    INPUT SOURCES                         │
├────────────────────────┬─────────────────────────────────┤
│  📄 Documents          │  🌐 Network Flow Data           │
│  (TXT, PDF, CSV, DOCX) │  (CICIDS2017-format CSV)        │
└────────┬───────────────┴──────────────┬──────────────────┘
         │                              │
         ▼                              ▼
┌────────────────────┐    ┌──────────────────────────┐
│  Document Scanner  │    │    Network IDS Module     │
│  TF-IDF + LinearSVC│    │  RandomForest Classifier  │
│  (8 attack types)  │    │  (14 attack types)        │
└────────┬───────────┘    └──────────────┬─────────────┘
         │                              │
         ▼                              ▼
┌──────────────────────────────────────────────────────────┐
│              MITRE ATT&CK Mapping Engine                 │
│         technique ID → tactic → kill chain stage         │
└────────────────────────┬─────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────┐
│              Attack Chain Reconstruction                 │
│  Groups alerts by time/source → orders on kill chain     │
│  Recon → Initial Access → Execution → ... → Impact      │
└────────────────────────┬─────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────┐
│               Streamlit Dashboard                        │
│  📄 Document Scanner  │  🌐 Network IDS                  │
│  ⛓️ Attack Chain       │  🗺️ MITRE Heatmap               │
└──────────────────────────────────────────────────────────┘
```

---

## 🤖 ML Models

### Model 1: Document Threat Classifier

| Aspect | Detail |
|--------|--------|
| **Algorithm** | LinearSVC + CalibratedClassifierCV |
| **Features** | TF-IDF (word n-grams 1-3 + char n-grams 3-5) |
| **Input** | Text extracted from documents (TXT, PDF, CSV, DOCX) |
| **Classes** | 8 attack categories |
| **Training Data** | `Attack_Dataset.csv` — attack scenario descriptions |

**Attack Categories:**
Command & Scripting Interpreter, Phishing, Masquerading, OS Credential Dumping, Brute Force, Shoulder Surfing, DDoS, Insider Threat

### Model 2: Network Flow Classifier

| Aspect | Detail |
|--------|--------|
| **Algorithm** | RandomForestClassifier |
| **Features** | 78 numeric network flow features (duration, packet counts, bytes, flags, IAT, etc.) |
| **Input** | Network flow records (CICIDS2017 format) |
| **Classes** | 14 attack categories + BENIGN |
| **Training Data** | CICIDS2017 dataset (curated subset) |

**Attack Categories:**
DDoS, DoS (Hulk/GoldenEye/Slowloris/Slowhttptest), PortScan, Bot, Infiltration, Web Attack (Brute Force/XSS/SQL Injection), FTP-Patator, SSH-Patator, Heartbleed

---

## 📂 Project Structure

```
MajorProject/
├── Dashboard/
│   └── app.py                      # Multi-tab Streamlit dashboard
├── Dataset/
│   ├── Attack_Dataset.csv           # Document attack descriptions
│   └── network/                     # Network flow datasets
│       └── cicids2017_sample.csv
├── analysis/
│   ├── attack_analyzer.py           # MITRE technique enrichment
│   ├── attack_chain.py              # Kill chain reconstruction engine
│   ├── mitre_knowledge_base.py      # MITRE ATT&CK technique database
│   └── network_mitre_map.py         # Network attack → MITRE mapping
├── core/
│   ├── folder_watcher.py            # Downloads folder auto-scanner
│   ├── detection_pipeline.py        # Unified detection orchestrator
│   └── log_ingestion.py             # Network CSV/log reader
├── detection/
│   ├── detect_attack.py             # Document attack detector (CLI)
│   ├── feature_extractor.py         # TF-IDF feature extraction
│   ├── file_parser.py               # Multi-format text extractor
│   └── network_detector.py          # Network flow classifier
├── scripts/
│   ├── train_model.py               # Train document classifier
│   ├── train_network_model.py       # Train network classifier
│   ├── predict.py                   # Batch prediction demo
│   └── confusion_matrix.py          # Model evaluation
├── logs/                            # Detection logs
├── requirements.txt
└── README.md
```

---

## 🗺️ MITRE ATT&CK Coverage

| MITRE ID | Technique Name | Kill Chain Stage | Detected By |
|----------|---------------|------------------|-------------|
| T1566 | Phishing | Initial Access | 📄 Document Scanner |
| T1190 | Exploit Public-Facing Application | Initial Access | 🌐 Network IDS |
| T1059 | Command & Scripting Interpreter | Execution | 📄 Document Scanner |
| T1036 | Masquerading | Defense Evasion | 📄 Document Scanner |
| T1003 | OS Credential Dumping | Credential Access | 📄 Document Scanner |
| T1110 | Brute Force | Credential Access | 📄 + 🌐 Both |
| T1056 | Input Capture / Shoulder Surfing | Collection | 📄 Document Scanner |
| T1046 | Network Service Scanning | Discovery | 🌐 Network IDS |
| T1071 | Application Layer Protocol | Command & Control | 🌐 Network IDS |
| T1499 | Endpoint Denial of Service | Impact | 📄 + 🌐 Both |
| T1078 | Valid Accounts / Insider Threat | Persistence | 📄 Document Scanner |
| T1583 | Botnet Infrastructure | Resource Development | 🌐 Network IDS |

---

## 🚀 Execution Plan

### Phase 1: Network IDS Module
- [ ] Integrate CICIDS2017 dataset (curated subset, ~200K rows)
- [ ] Build `train_network_model.py` — RandomForest on 78 flow features
- [ ] Build `network_detector.py` — inference module for flow classification
- [ ] Build `log_ingestion.py` — CSV/log file reader and normalizer
- [ ] Create MITRE mappings for all network attack types

### Phase 2: Attack Chain Engine
- [ ] Build `attack_chain.py` — kill chain reconstruction
- [ ] Map all techniques to MITRE ATT&CK tactics (14 kill chain stages)
- [ ] Implement alert correlation (time-window + source grouping)
- [ ] Generate attack progression narratives

### Phase 3: Enhanced Dashboard
- [ ] Tab 1: Document Scanner (existing, polished)
- [ ] Tab 2: Network IDS (upload CSV → batch detection + stats)
- [ ] Tab 3: Attack Chain Timeline (kill chain visualization)
- [ ] Tab 4: MITRE ATT&CK Heatmap (technique coverage grid)

### Phase 4: Integration & Polish
- [ ] Unified detection pipeline (`detection_pipeline.py`)
- [ ] End-to-end testing with sample data
- [ ] Final documentation and README

---

## 🛠️ Setup & Installation

```bash
# Clone the repository
git clone <repo-url>
cd MajorProject

# Create virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux/Mac

# Install dependencies
pip install -r requirements.txt
```

## 📊 Train Models

```bash
# Train document classifier (8 attack categories)
python scripts/train_model.py

# Train network flow classifier (14 attack categories)
python scripts/train_network_model.py
```

## ▶️ Run Dashboard

```bash
streamlit run Dashboard/app.py
```

---

## 🔧 Tech Stack

| Component | Technology |
|-----------|-----------|
| ML (Documents) | scikit-learn (LinearSVC), TF-IDF |
| ML (Network) | scikit-learn (RandomForest) |
| Feature Engineering | TF-IDF vectorizers, StandardScaler |
| Dashboard | Streamlit |
| Visualization | Plotly, Matplotlib |
| Data Processing | Pandas, NumPy, SciPy |
| File Parsing | PyPDF2, python-docx |
| File Monitoring | Watchdog |

---

## 📜 License

This project is developed as an academic Major Project.
=======
# major-project
>>>>>>> e08965267bd86b9080a6051a2154a9ebdd8a92ba
