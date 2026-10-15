from functools import lru_cache
import json
from pathlib import Path

import joblib
import pandas as pd

from services.detection_rules import rule_alert_reasons

BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_DIR = BASE_DIR / "ml_models"


class AnomalyDetector:
    def __init__(self):
        self.pipeline = joblib.load(MODEL_DIR / "isolation_forest.joblib")
        self.features = joblib.load(MODEL_DIR / "features.joblib")
        threshold_path = MODEL_DIR / "threshold.json"
        if threshold_path.exists():
            threshold_data = json.loads(threshold_path.read_text(encoding="utf-8"))
            self.threshold = float(threshold_data["decision_function_threshold"])
        else:
            self.threshold = None

    def score(self, log_entry):
        record = {feature: log_entry[feature] for feature in self.features}
        data = pd.DataFrame([record], columns=self.features)
        anomaly_score = float(self.pipeline.decision_function(data)[0])
        isolation_forest_alert = (
            self.threshold is not None and anomaly_score <= self.threshold
        )
        if self.threshold is None:
            isolation_forest_alert = int(self.pipeline.predict(data)[0]) == -1

        methods = []
        if isolation_forest_alert:
            methods.append("isolation_forest")
        methods.extend(
            f"rule:{reason}" for reason in rule_alert_reasons(log_entry)
        )
        return bool(methods), anomaly_score, methods


@lru_cache(maxsize=1)
def get_detector():
    return AnomalyDetector()
