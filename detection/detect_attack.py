import sys
import joblib
from feature_extractor import extract_features_from_log

# Load model
model = joblib.load("attack_model.pkl")
encoder = joblib.load("label_encoder.pkl")

def detect_attack(file_path):

    with open(file_path, "r", encoding="utf-8") as f:
        text = f.read()

    features = extract_features_from_log(text)

    prediction = model.predict(features)

    attack = encoder.inverse_transform(prediction)[0]

    print("\nDetected Attack:", attack)


if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: python detect_attack.py <logfile>")
        sys.exit()

    detect_attack(sys.argv[1])