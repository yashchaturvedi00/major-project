import pandas as pd
import joblib
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay

# Load trained model
model = joblib.load("attack_classification_model.pkl")

# Load dataset
df = pd.read_csv("Dataset/processed_attack_dataset.csv")

# Features and true labels
X = df.drop(columns=["mitre_attack_id"])
y_true = df["mitre_attack_id"]

# Predict
y_pred = model.predict(X)

# Create confusion matrix
cm = confusion_matrix(y_true, y_pred)

# 🔑 Map class numbers to MITRE IDs
label_map = {
    0: "T1110",  # Brute Force
    1: "T1499",  # DoS
    2: "T1059"   # Command Execution (if present)
}

# Convert numeric labels to MITRE labels
display_labels = [label_map[i] for i in sorted(label_map.keys())[:cm.shape[0]]]

# Plot confusion matrix with labels
disp = ConfusionMatrixDisplay(
    confusion_matrix=cm,
    display_labels=display_labels
)

disp.plot(cmap="Blues", values_format="d")
plt.title("Confusion Matrix – MITRE Attack Classification")
plt.xlabel("Predicted Attack")
plt.ylabel("Actual Attack")
plt.show()

