import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import joblib
import pandas as pd
from fastapi.testclient import TestClient

from api import main
from api.detection import BASE_DIR


class FixedDetector:
    def __init__(self, is_anomaly):
        self.is_anomaly = is_anomaly

    def score(self, _log_entry):
        return self.is_anomaly, -0.25 if self.is_anomaly else 0.1


class AlertsApiTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp_dir.name) / "test.sqlite3"
        self.database_patch = patch.object(main, "DATABASE_PATH", self.database_path)
        self.database_patch.start()
        self.detector_patch = patch.object(main, "get_detector", return_value=FixedDetector(True))
        self.detector_patch.start()
        self.triage_patch = patch.object(
            main.triage_service,
            "triage_anomaly",
            return_value={
                "tactic": "Initial Access",
                "severity": "HIGH",
                "summary": "Suspicious login activity was detected. Review the affected host.",
                "remediation": ["Block the source IP.", "Review login records.", "Require MFA."],
            },
        )
        self.triage_patch.start()
        self.client_context = TestClient(main.app)
        self.client = self.client_context.__enter__()

    def tearDown(self):
        self.client_context.__exit__(None, None, None)
        self.triage_patch.stop()
        self.detector_patch.stop()
        self.database_patch.stop()
        self.temp_dir.cleanup()

    @staticmethod
    def log_payload():
        return {
            "timestamp": "2026-10-09T14:32:01Z",
            "source_ip": "45.22.11.90",
            "dest_ip": "10.0.4.15",
            "dest_port": 22,
            "protocol": "TCP",
            "bytes_transferred": 1054300,
            "failed_login_attempts": 12,
            "user_agent": "Nmap Scripting Engine",
            "geo_location": "RU",
        }

    def test_anomaly_is_triaged_persisted_and_listed(self):
        response = self.client.post("/api/logs/", json=self.log_payload())

        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertTrue(result["is_anomaly"])
        self.assertEqual(result["alert"]["severity"], "HIGH")
        self.assertEqual(len(result["alert"]["remediation"]), 3)

        alerts = self.client.get("/api/alerts/?severity=high")
        self.assertEqual(alerts.status_code, 200)
        self.assertEqual(len(alerts.json()), 1)
        self.assertEqual(alerts.json()[0]["raw_log"]["source_ip"], "45.22.11.90")

    def test_benign_log_does_not_create_alert(self):
        with patch.object(main, "get_detector", return_value=FixedDetector(False)):
            response = self.client.post("/api/logs/", json=self.log_payload())

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["is_anomaly"])
        self.assertIsNone(response.json()["alert"])
        self.assertEqual(self.client.get("/api/alerts/").json(), [])

    def test_invalid_network_log_is_rejected(self):
        payload = self.log_payload()
        payload["dest_port"] = 70000

        response = self.client.post("/api/logs/", json=payload)

        self.assertEqual(response.status_code, 422)


class DetectorBenchmarkTests(unittest.TestCase):
    def test_detector_meets_synthetic_benchmark(self):
        data = pd.read_csv(BASE_DIR / "scripts" / "network_logs.csv")
        features = joblib.load(BASE_DIR / "ml_models" / "features.joblib")
        detector = joblib.load(BASE_DIR / "ml_models" / "isolation_forest.joblib")
        predictions = detector.predict(data[features]) == -1
        malicious = data["label"] == 1

        true_positives = int((predictions & malicious).sum())
        false_positives = int((predictions & ~malicious).sum())

        self.assertGreaterEqual(true_positives, 45)
        self.assertLessEqual(false_positives, 10)
