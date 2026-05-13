import pandas as pd
import joblib
import time
from analysis.attack_analyzer import analyze_attack

# Load trained model
model = joblib.load("attack_classification_model.pkl")

import pandas as pd
import joblib
import time
import numpy as np
from analysis.attack_analyzer import analyze_attack

# Load trained model
model = joblib.load("attack_classification_model.pkl")

# Load dataset
df = pd.read_csv("Dataset/processed_attack_dataset.csv")

# Pick 5 random samples
samples = df.sample(5)

print("\n===== RUNNING ANALYSIS ON 5 RANDOM ATTACKS =====\n")

for idx, row in samples.iterrows():

    # Prepare input features
    sample_features = row.drop("mitre_attack_id").to_frame().T

    start = time.time()

    # Prediction
    predicted_class = model.predict(sample_features)[0]

    # 🔑 Confidence calculation
    probabilities = model.predict_proba(sample_features)[0]
    confidence = round(np.max(probabilities) * 100, 2)

    end = time.time()
    detection_time = round(end - start, 4)

    # Analysis
    result = analyze_attack(predicted_class, detection_time)

    print("----- ATTACK DETECTED -----")
    for key, value in result.items():
        if isinstance(value, list):
            print(f"{key}:")
            for v in value:
                print("-", v)
        else:
            print(f"{key}: {value}")

    print(f"Accuracy Score: {confidence}%")
    print()
    

