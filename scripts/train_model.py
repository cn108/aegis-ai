from pathlib import Path

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, RobustScaler

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_PATH = BASE_DIR / "scripts" / "network_logs.csv"
MODEL_DIR = BASE_DIR / "ml_models"
FEATURES = [
    "dest_port",
    "protocol",
    "bytes_transferred",
    "failed_login_attempts",
    "geo_location",
    "user_agent",
]
NUMERIC_FEATURES = ["dest_port", "bytes_transferred", "failed_login_attempts"]
CATEGORICAL_FEATURES = ["protocol", "geo_location", "user_agent"]


def train_model():
    if not DATA_PATH.exists():
        raise FileNotFoundError(f"{DATA_PATH} not found. Run generate_logs.py first.")

    data = pd.read_csv(DATA_PATH)
    required_columns = set(FEATURES + ["label"])
    missing_columns = required_columns.difference(data.columns)
    if missing_columns:
        raise ValueError(f"Training data is missing columns: {sorted(missing_columns)}")
    if data.empty or data["label"].nunique() < 2:
        raise ValueError("Training data must contain benign and malicious records.")

    preprocessor = ColumnTransformer(
        transformers=[
            ("numeric", RobustScaler(), NUMERIC_FEATURES),
            ("categorical", OneHotEncoder(handle_unknown="ignore"), CATEGORICAL_FEATURES),
        ]
    )
    detector = Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            (
                "isolation_forest",
                IsolationForest(
                    n_estimators=200,
                    contamination=0.005,
                    max_samples=1024,
                    random_state=42,
                ),
            ),
        ]
    )
    features = data[FEATURES]

    print("Training Isolation Forest...")
    detector.fit(features)

    predictions = detector.predict(features) == -1
    labels = data["label"] == 1
    true_positives = int((predictions & labels).sum())
    false_positives = int((predictions & ~labels).sum())
    false_negatives = int((~predictions & labels).sum())
    malicious_count = int(labels.sum())
    print(f"True positives: {true_positives}/{malicious_count}")
    print(f"False positives: {false_positives}")
    print(f"False negatives: {false_negatives}")

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(detector, MODEL_DIR / "isolation_forest.joblib")
    joblib.dump(FEATURES, MODEL_DIR / "features.joblib")
    print(f"Model and preprocessing pipeline saved to {MODEL_DIR}")

if __name__ == "__main__":
    train_model()
