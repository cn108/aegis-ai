from pathlib import Path

import joblib
import json
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import RobustScaler

from services.detection_rules import rule_alert_reasons

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_PATH = BASE_DIR / "scripts" / "network_logs.csv"
MODEL_DIR = BASE_DIR / "ml_models"
TARGET_VALIDATION_FPR = 0.01
FEATURES = [
    "dest_port",
    "bytes_transferred",
    "failed_login_attempts",
]


def train_model():
    if not DATA_PATH.exists():
        raise FileNotFoundError(f"{DATA_PATH} not found. Run generate_logs.py first.")

    data = pd.read_csv(DATA_PATH)
    required_columns = set(FEATURES + ["label"])
    missing_columns = required_columns.difference(data.columns)
    if missing_columns:
        raise ValueError(f"Training data is missing columns: {sorted(missing_columns)}")
    if data.empty or set(data["label"].unique()) != {0, 1}:
        raise ValueError("Training data must contain benign and malicious records.")

    benign = data.loc[data["label"] == 0].reset_index(drop=True)
    malicious = data.loc[data["label"] == 1].reset_index(drop=True)
    training_benign, held_out_benign = train_test_split(
        benign,
        test_size=0.30,
        random_state=42,
    )
    validation_benign, test_benign = train_test_split(
        held_out_benign,
        test_size=0.50,
        random_state=43,
    )
    test_data = pd.concat([test_benign, malicious], ignore_index=True)
    detector = Pipeline(
        steps=[
            ("scaler", RobustScaler()),
            (
                "isolation_forest",
                IsolationForest(
                    n_estimators=300,
                    contamination="auto",
                    max_samples=1024,
                    random_state=42,
                ),
            ),
        ]
    )
    features = training_benign[FEATURES]

    print(
        f"Training on {len(training_benign)} benign rows; "
        f"validation={len(validation_benign)} benign rows; "
        f"test={len(test_benign)} benign + {len(malicious)} malicious rows."
    )
    detector.fit(features)

    validation_scores = detector.decision_function(validation_benign[FEATURES])
    threshold = float(
        pd.Series(validation_scores).quantile(TARGET_VALIDATION_FPR, interpolation="linear")
    )
    test_scores = detector.decision_function(test_data[FEATURES])
    test_labels = test_data["label"].to_numpy(dtype=int)
    predictions = test_scores <= threshold
    tn, fp, fn, tp = confusion_matrix(test_labels, predictions, labels=[0, 1]).ravel()
    isolation_forest = {
        "true_positives": int(tp),
        "false_positives": int(fp),
        "true_negatives": int(tn),
        "false_negatives": int(fn),
        "precision": float(precision_score(test_labels, predictions, zero_division=0)),
        "recall": float(recall_score(test_labels, predictions, zero_division=0)),
        "f1": float(f1_score(test_labels, predictions, zero_division=0)),
        "false_positive_rate": float(fp / (fp + tn)) if fp + tn else 0.0,
        "roc_auc": float(roc_auc_score(test_labels, -test_scores)),
        "average_precision": float(average_precision_score(test_labels, -test_scores)),
    }
    rule_predictions = test_data.apply(
        lambda row: bool(rule_alert_reasons(row)), axis=1
    ).to_numpy(dtype=bool)
    rule_tn, rule_fp, rule_fn, rule_tp = confusion_matrix(
        test_labels, rule_predictions, labels=[0, 1]
    ).ravel()
    rule_baseline = {
        "true_positives": int(rule_tp),
        "false_positives": int(rule_fp),
        "true_negatives": int(rule_tn),
        "false_negatives": int(rule_fn),
        "precision": float(precision_score(test_labels, rule_predictions, zero_division=0)),
        "recall": float(recall_score(test_labels, rule_predictions, zero_division=0)),
        "f1": float(f1_score(test_labels, rule_predictions, zero_division=0)),
        "false_positive_rate": float(rule_fp / (rule_fp + rule_tn)) if rule_fp + rule_tn else 0.0,
    }
    hybrid_predictions = predictions | rule_predictions
    hybrid_tn, hybrid_fp, hybrid_fn, hybrid_tp = confusion_matrix(
        test_labels, hybrid_predictions, labels=[0, 1]
    ).ravel()
    hybrid_baseline = {
        "true_positives": int(hybrid_tp),
        "false_positives": int(hybrid_fp),
        "true_negatives": int(hybrid_tn),
        "false_negatives": int(hybrid_fn),
        "precision": float(precision_score(test_labels, hybrid_predictions, zero_division=0)),
        "recall": float(recall_score(test_labels, hybrid_predictions, zero_division=0)),
        "f1": float(f1_score(test_labels, hybrid_predictions, zero_division=0)),
        "false_positive_rate": float(hybrid_fp / (hybrid_fp + hybrid_tn))
        if hybrid_fp + hybrid_tn
        else 0.0,
    }
    evaluation = {
        "dataset": "synthetic",
        "split_seed": 42,
        "threshold_policy": {
            "method": "validation_benign_score_quantile",
            "target_validation_false_positive_rate": TARGET_VALIDATION_FPR,
            "threshold": threshold,
        },
        "row_counts": {
            "training_benign": int(len(training_benign)),
            "validation_benign": int(len(validation_benign)),
            "test_benign": int(len(test_benign)),
            "test_malicious": int(len(malicious)),
        },
        "models": {
            "isolation_forest": isolation_forest,
            "synthetic_rule_baseline": rule_baseline,
            "hybrid": hybrid_baseline,
        },
        "limitations": (
            "Synthetic-only benchmark; rule baseline encodes the generator's attack "
            "patterns. This is not evidence of production network detection performance."
        ),
    }
    print("Held-out test metrics (synthetic data; not a production estimate):")
    print(f"  Isolation Forest: {isolation_forest}")
    print(f"  Rule baseline: {rule_baseline}")
    print(f"  Hybrid: {hybrid_baseline}")

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(detector, MODEL_DIR / "isolation_forest.joblib")
    joblib.dump(FEATURES, MODEL_DIR / "features.joblib")
    (MODEL_DIR / "threshold.json").write_text(
        json.dumps(
            {
                "decision_function_threshold": threshold,
                "target_validation_false_positive_rate": TARGET_VALIDATION_FPR,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (MODEL_DIR / "evaluation.json").write_text(
        json.dumps(evaluation, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Model and preprocessing pipeline saved to {MODEL_DIR}")

if __name__ == "__main__":
    train_model()
