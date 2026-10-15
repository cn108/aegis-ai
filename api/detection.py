from functools import lru_cache
from pathlib import Path

import joblib
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_DIR = BASE_DIR / "ml_models"


class AnomalyDetector:
    def __init__(self):
        self.pipeline = joblib.load(MODEL_DIR / "isolation_forest.joblib")
        self.features = joblib.load(MODEL_DIR / "features.joblib")

    def score(self, log_entry):
        record = {feature: log_entry[feature] for feature in self.features}
        data = pd.DataFrame([record], columns=self.features)
        prediction = int(self.pipeline.predict(data)[0])
        anomaly_score = float(self.pipeline.decision_function(data)[0])
        return prediction == -1, anomaly_score


@lru_cache(maxsize=1)
def get_detector():
    return AnomalyDetector()
