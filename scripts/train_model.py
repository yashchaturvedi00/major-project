import pandas as pd
import joblib
import numpy as np
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import classification_report
from scipy.sparse import hstack

print("=" * 60)
print("  ATTACK CLASSIFICATION MODEL TRAINING")
print("  Target: 8 Specific Attack Categories")
print("=" * 60)

# ── 1. Load dataset ──────────────────────────────────────────
print("\n[1/7] Loading dataset...")
df = pd.read_csv("Dataset/Attack_Dataset.csv")
print(f"  Total samples: {df.shape[0]}")

# ── 2. Define the 8 target attack categories ─────────────────
print("\n[2/7] Mapping to 8 target attack categories...")

# Keywords used to classify each row into one of the 8 categories.
# We check Attack Type, Category, Title, and MITRE Technique columns.
TARGET_CATEGORIES = {
    "Command & Scripting Interpreter": {
        "attack_type_kw": ["command injection", "script injection", "code execution",
                           "remote shell", "command execution", "rce", "scripting",
                           "javascript injection", "webview exploit", "interpreter",
                           "powershell", "cmd.exe", "bash injection", "code injection",
                           "xss", "cross-site scripting"],
        "category_kw": ["cross-site scripting"],
        "mitre_kw": ["T1059"],
    },
    "Phishing": {
        "attack_type_kw": ["phishing", "spear phishing", "smishing", "vishing",
                           "social engineering", "fake login", "captive portal",
                           "credential harvesting", "email malware", "spoof email",
                           "whaling", "fake app"],
        "category_kw": ["email & messaging"],
        "mitre_kw": ["T1566", "T1598"],
    },
    "Masquerading": {
        "attack_type_kw": ["masquerad", "impersonat", "disguise", "fake certificate",
                           "ssl cert", "binary masquerad", "process masquerad",
                           "path masquerad", "hta masquerade", "forged", "spoofing identity"],
        "category_kw": [],
        "mitre_kw": ["T1036"],
    },
    "OS Credential Dumping": {
        "attack_type_kw": ["credential dump", "hash dump", "pass the hash",
                           "mimikatz", "lsass", "sam dump", "ntds", "credential theft",
                           "password extraction", "credential reuse", "credential relay",
                           "token theft", "password spray", "credential brute"],
        "category_kw": [],
        "mitre_kw": ["T1003"],
    },
    "Brute Force": {
        "attack_type_kw": ["brute force", "brute-force", "password guessing",
                           "dictionary attack", "credential stuffing", "login attack",
                           "authentication bypass", "failed login", "account lockout"],
        "category_kw": [],
        "mitre_kw": ["T1110"],
    },
    "Shoulder Surfing": {
        "attack_type_kw": ["shoulder surf", "visual hacking", "screen capture",
                           "keylogger", "keystroke", "screen recording",
                           "clipboard hijack", "smudge attack", "screen spy",
                           "input capture"],
        "category_kw": [],
        "mitre_kw": ["T1056"],
    },
    "DDoS": {
        "attack_type_kw": ["ddos", "denial of service", "dos attack", "resource exhaustion",
                           "bandwidth exhaustion", "flood", "amplification",
                           "reflection", "syn flood", "slowloris", "traffic spike",
                           "volumetric attack", "rate limit"],
        "category_kw": [],
        "mitre_kw": ["T1499", "T1498"],
    },
    "Insider Threat": {
        "attack_type_kw": ["insider", "data exfiltration", "unauthorized access",
                           "privilege abuse", "sabotage", "rogue employee",
                           "internal threat", "data leak", "policy violation",
                           "misuse of", "unauthorized download"],
        "category_kw": ["insider threat"],
        "mitre_kw": ["T1078"],
    },
}


def classify_row(row):
    """Classify a dataset row into one of the 8 target categories."""
    attack_type = str(row.get("Attack Type", "")).lower()
    category = str(row.get("Category", "")).lower()
    title = str(row.get("Title", "")).lower()
    mitre = str(row.get("MITRE Technique", "")).upper()
    combined = f"{attack_type} {title}"

    for target_cat, rules in TARGET_CATEGORIES.items():
        # Check MITRE technique ID
        for mid in rules["mitre_kw"]:
            if mid in mitre:
                return target_cat

        # Check attack type and title keywords
        for kw in rules["attack_type_kw"]:
            if kw in combined:
                return target_cat

        # Check category keywords
        for kw in rules["category_kw"]:
            if kw in category:
                return target_cat

    return None  # Does not match any target category


# Apply classification
df["target_label"] = df.apply(classify_row, axis=1)

# Drop rows that don't match any target category
df = df.dropna(subset=["target_label", "Scenario Description"])
df["Scenario Description"] = df["Scenario Description"].astype(str).str.strip()

print(f"  Samples matching target categories: {df.shape[0]}")
print(f"  Category distribution:")
for cat, count in df["target_label"].value_counts().items():
    print(f"    {cat}: {count}")

# ── 3. Feature extraction with TF-IDF ───────────────────────
print("\n[3/7] Extracting TF-IDF features from text...")

text_column = "Scenario Description"
extra_cols = ["Title", "Tools Used", "Vulnerability", "Target Type",
              "Impact", "Detection Method", "Attack Steps "]
df["combined_text"] = df[text_column]
for col in extra_cols:
    if col in df.columns:
        df["combined_text"] = df["combined_text"] + " " + df[col].fillna("").astype(str)

tfidf_word = TfidfVectorizer(
    max_features=15000,
    ngram_range=(1, 4),
    sublinear_tf=True,
    min_df=2,
    max_df=0.95,
    strip_accents="unicode",
    stop_words="english",
    token_pattern=r"(?u)\b\w+\b|[^\w\s]",  # CAPTURE PUNCTUATION (- / \ . etc are vital for scripts)
    analyzer="word"
)

tfidf_char = TfidfVectorizer(
    max_features=5000,
    ngram_range=(3, 5),
    sublinear_tf=True,
    min_df=2,
    max_df=0.95,
    strip_accents="unicode",
    analyzer="char_wb"
)

X_word = tfidf_word.fit_transform(df["combined_text"])
X_char = tfidf_char.fit_transform(df["combined_text"])
X = hstack([X_word, X_char])
print(f"  TF-IDF matrix shape: {X.shape} (word + char n-grams)")

# ── 4. Encode labels ────────────────────────────────────────
print("\n[4/7] Encoding labels...")
encoder = LabelEncoder()
y = encoder.fit_transform(df["target_label"])
print(f"  Number of classes: {len(encoder.classes_)}")
for i, cls in enumerate(encoder.classes_):
    print(f"    [{i}] {cls}")

# ── 5. Train model ──────────────────────────────────────────
print("\n[5/7] Training model...")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

base_model = LinearSVC(
    C=5.0,  # Increased regularization parameter for sharper decision boundaries
    max_iter=5000,
    random_state=42,
    class_weight="balanced",
    dual="auto"
)

model = CalibratedClassifierCV(base_model, cv=5, method="isotonic") # Isotonic calibration often yields better confidence scores
model.fit(X_train, y_train)

# ── 6. Evaluate ─────────────────────────────────────────────
print("\n[6/7] Evaluating model...")

train_acc = model.score(X_train, y_train)
test_acc = model.score(X_test, y_test)

print(f"\n  Training Accuracy: {train_acc * 100:.2f}%")
print(f"  Testing Accuracy:  {test_acc * 100:.2f}%")

cv_scores = cross_val_score(model, X, y, cv=5, scoring="accuracy", n_jobs=-1)
print(f"  Cross-Val Accuracy: {cv_scores.mean() * 100:.2f}% (+/- {cv_scores.std() * 100:.2f}%)")

# Detailed classification report
print("\n  Classification Report:")
y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred, target_names=encoder.classes_))

# ── 7. Save artifacts ────────────────────────────────────────
print("\n[7/7] Saving model artifacts...")

joblib.dump(model, "attack_model.pkl")
joblib.dump(encoder, "label_encoder.pkl")
joblib.dump(tfidf_word, "tfidf_vectorizer.pkl")
joblib.dump(tfidf_char, "tfidf_char_vectorizer.pkl")

# Build MITRE ATT&CK mapping for the 8 categories
CATEGORY_MITRE_MAP = {
    "Command & Scripting Interpreter": "T1059",
    "Phishing": "T1566",
    "Masquerading": "T1036",
    "OS Credential Dumping": "T1003",
    "Brute Force": "T1110",
    "Shoulder Surfing": "T1056",
    "DDoS": "T1499",
    "Insider Threat": "T1078",
}

MITRE_KB = {
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
        "impact": "Remote code execution, system compromise, lateral movement",
        "category": "Execution",
        "mitigation": "Restrict script execution policies, monitor command-line activity, use application whitelisting, disable unused scripting engines.",
        "detection_method": "Monitor process creation, command-line arguments, script execution logs, and unusual interpreter usage.",
    },
    "T1566": {
        "name": "Phishing",
        "description": "Adversaries may send phishing messages to gain access to victim systems, often via malicious attachments or links.",
        "impact": "Initial access, credential theft, malware delivery",
        "category": "Initial Access",
        "mitigation": "User training, email filtering, URL scanning, multi-factor authentication, sandboxing attachments.",
        "detection_method": "Monitor email gateways, analyze URLs and attachments, track user click behavior on suspicious links.",
    },
    "T1036": {
        "name": "Masquerading",
        "description": "Adversaries may manipulate features of their artifacts to make them appear legitimate or benign to users and security tools.",
        "impact": "Defense evasion, persistence, deception of security tools",
        "category": "Defense Evasion",
        "mitigation": "File integrity monitoring, code signing enforcement, process monitoring, block execution from suspicious paths.",
        "detection_method": "Compare file names vs expected locations, verify digital signatures, monitor for renamed system utilities.",
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "description": "Adversaries may attempt to dump credentials from the operating system to obtain account login credentials.",
        "impact": "Credential access, lateral movement, privilege escalation",
        "category": "Credential Access",
        "mitigation": "Credential Guard, restrict access to LSASS, disable WDigest, use Protected Users group, limit admin privileges.",
        "detection_method": "Monitor access to LSASS process, SAM registry hive, NTDS.dit, and credential-related API calls.",
    },
    "T1110": {
        "name": "Brute Force",
        "description": "Adversaries may use brute force techniques to attempt access to accounts through systematic password guessing.",
        "impact": "Account compromise, unauthorized access, lateral movement",
        "category": "Credential Access",
        "mitigation": "Account lockout policies, MFA, strong password requirements, rate limiting, CAPTCHA on login endpoints.",
        "detection_method": "Monitor failed login attempts, unusual authentication patterns, login attempts from unusual locations.",
    },
    "T1056": {
        "name": "Input Capture / Shoulder Surfing",
        "description": "Adversaries may capture user input through keylogging, screen capture, or physical observation (shoulder surfing).",
        "impact": "Credential theft, data exposure, privacy violation",
        "category": "Collection",
        "mitigation": "Privacy screens, security awareness training, anti-keylogger software, screen lock policies, clean desk policy.",
        "detection_method": "Detect keylogger processes, monitor for screen capture APIs, physical security awareness programs.",
    },
    "T1499": {
        "name": "Endpoint Denial of Service (DDoS)",
        "description": "Adversaries may perform denial of service attacks to degrade or block availability of targeted resources.",
        "impact": "Service downtime, revenue loss, reputation damage",
        "category": "Impact",
        "mitigation": "Rate limiting, traffic filtering, CDN/DDoS protection services, resource monitoring, auto-scaling.",
        "detection_method": "Monitor network traffic volumes, connection rates, resource utilization, and unusual traffic patterns.",
    },
    "T1078": {
        "name": "Valid Accounts / Insider Threat",
        "description": "Adversaries or malicious insiders may use legitimate credentials to gain access, move laterally, or exfiltrate data.",
        "impact": "Data exfiltration, sabotage, unauthorized access, privilege abuse",
        "category": "Initial Access / Persistence",
        "mitigation": "Least privilege access, behavior analytics (UEBA), DLP systems, separation of duties, exit process controls.",
        "detection_method": "User behavior analytics, off-hours access monitoring, unusual data access patterns, privilege escalation events.",
    },
}

joblib.dump(CATEGORY_MITRE_MAP, "attack_to_mitre_map.pkl")
joblib.dump(MITRE_KB, "mitre_kb.pkl")

print(f"  Saved: attack_model.pkl, label_encoder.pkl")
print(f"  Saved: tfidf_vectorizer.pkl, tfidf_char_vectorizer.pkl")
print(f"  Saved: attack_to_mitre_map.pkl, mitre_kb.pkl")

print("\n" + "=" * 60)
print(f"  ✅ Model trained successfully!")
print(f"  📊 Test Accuracy: {test_acc * 100:.2f}%")
print(f"  🎯 8 Attack Categories: {list(CATEGORY_MITRE_MAP.keys())}")
print("=" * 60)