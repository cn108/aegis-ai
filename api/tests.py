import asyncio
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api import main
from api.detection import BASE_DIR
from services.llm_triage import LLMTriageService


class FixedDetector:
    def __init__(self, is_anomaly):
        self.is_anomaly = is_anomaly

    def score(self, _log_entry):
        return (
            self.is_anomaly,
            -0.25 if self.is_anomaly else 0.1,
            ["rule:failed_login_attempts"] if self.is_anomaly else [],
        )


class AlertsApiTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp_dir.name) / "test.sqlite3"
        self.database_patch = patch.object(main, "DATABASE_PATH", self.database_path)
        self.database_patch.start()
        self.token_patch = patch.object(main, "API_AUTH_TOKEN", "t" * 48)
        self.token_patch.start()
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
        self.client_context = TestClient(
            main.app,
            headers={"Authorization": "Bearer " + ("t" * 48)},
        )
        self.client = self.client_context.__enter__()

    def tearDown(self):
        self.client_context.__exit__(None, None, None)
        self.triage_patch.stop()
        self.detector_patch.stop()
        self.token_patch.stop()
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
        self.assertEqual(
            result["alert"]["detection_methods"], ["rule:failed_login_attempts"]
        )
        self.assertEqual(result["alert"]["review_status"], "pending_review")

        alerts = self.client.get("/api/alerts/?severity=high")
        self.assertEqual(alerts.status_code, 200)
        self.assertEqual(alerts.json()["total"], 1)
        self.assertEqual(len(alerts.json()["items"]), 1)
        self.assertEqual(alerts.json()["items"][0]["raw_log"]["source_ip"], "45.22.11.90")

    def test_benign_log_does_not_create_alert(self):
        with patch.object(main, "get_detector", return_value=FixedDetector(False)):
            response = self.client.post("/api/logs/", json=self.log_payload())

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["is_anomaly"])
        self.assertIsNone(response.json()["alert"])
        self.assertEqual(self.client.get("/api/alerts/").json()["items"], [])

    def test_invalid_network_log_is_rejected(self):
        payload = self.log_payload()
        payload["dest_port"] = 70000

        response = self.client.post("/api/logs/", json=payload)

        self.assertEqual(response.status_code, 422)

    def test_api_rejects_missing_or_invalid_bearer_token(self):
        with TestClient(main.app) as unauthenticated_client:
            missing = unauthenticated_client.get("/api/alerts/")
            invalid = unauthenticated_client.get(
                "/api/alerts/",
                headers={"Authorization": "Bearer " + "x" * 48},
            )

        self.assertEqual(missing.status_code, 401)
        self.assertEqual(invalid.status_code, 401)

    def test_api_fails_closed_when_authentication_is_not_configured(self):
        with patch.object(main, "API_AUTH_TOKEN", None):
            response = self.client.get("/api/alerts/")

        self.assertEqual(response.status_code, 503)

    def test_alert_review_is_filtered_and_audited(self):
        created = self.client.post("/api/logs/", json=self.log_payload()).json()["alert"]
        reviewed = self.client.patch(
            f"/api/alerts/{created['id']}/review",
            json={
                "review_status": "false_positive",
                "reviewer": "Analyst One",
                "note": "Expected maintenance traffic.",
            },
        )

        self.assertEqual(reviewed.status_code, 200)
        self.assertEqual(reviewed.json()["review_status"], "false_positive")
        filtered = self.client.get("/api/alerts/?review_status=false_positive")
        self.assertEqual(filtered.json()["total"], 1)
        history = self.client.get(f"/api/alerts/{created['id']}/history")
        self.assertEqual(history.status_code, 200)
        self.assertEqual([event["event_type"] for event in history.json()], [
            "alert.created",
            "alert.reviewed",
        ])
        self.assertEqual(history.json()[1]["actor"], "Analyst One")

    def test_triage_provider_failure_does_not_persist_alert(self):
        with patch.object(
            main.triage_service,
            "triage_anomaly",
            side_effect=RuntimeError("provider unavailable"),
        ):
            response = self.client.post("/api/logs/", json=self.log_payload())

        self.assertEqual(response.status_code, 502)
        self.assertEqual(self.client.get("/api/alerts/").json()["total"], 0)

    def test_dashboard_is_served(self):
        response = self.client.get("/dashboard")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Aegis AI Analyst Console", response.text)


class DatabaseMigrationTests(unittest.TestCase):
    def test_existing_alert_table_is_upgraded(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "legacy.sqlite3"
            with closing(sqlite3.connect(database_path)) as connection:
                connection.execute(
                    """
                    CREATE TABLE aegis_alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        source_ip TEXT NOT NULL,
                        dest_ip TEXT NOT NULL,
                        dest_port INTEGER NOT NULL,
                        anomaly_score REAL NOT NULL,
                        tactic TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        summary TEXT NOT NULL,
                        remediation TEXT NOT NULL,
                        raw_log TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    )
                    """
                )
            with patch.object(main, "DATABASE_PATH", database_path):
                main.initialize_database()
                with closing(main.get_connection()) as connection:
                    columns = {
                        row["name"]
                        for row in connection.execute(
                            "PRAGMA table_info(aegis_alerts)"
                        ).fetchall()
                    }
                    audit_table = connection.execute(
                        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
                        ("aegis_audit_events",),
                    ).fetchone()

        migrated_columns = {
            "detection_methods",
            "triage_source",
            "review_status",
            "reviewed_by",
            "review_note",
        }
        self.assertTrue(migrated_columns.issubset(columns))
        self.assertIsNotNone(audit_table)


class DetectorBenchmarkTests(unittest.TestCase):
    def test_detector_meets_synthetic_benchmark(self):
        evaluation = json.loads(
            (BASE_DIR / "ml_models" / "evaluation.json").read_text(encoding="utf-8")
        )
        self.assertEqual(evaluation["dataset"], "synthetic")
        self.assertEqual(evaluation["row_counts"]["training_benign"], 7000)
        self.assertEqual(evaluation["row_counts"]["test_malicious"], 50)
        self.assertEqual(
            evaluation["models"]["synthetic_rule_baseline"]["true_positives"], 50
        )
        self.assertEqual(
            evaluation["models"]["synthetic_rule_baseline"]["false_positives"], 0
        )
        self.assertGreaterEqual(evaluation["models"]["isolation_forest"]["roc_auc"], 0.8)
        self.assertGreaterEqual(evaluation["models"]["hybrid"]["recall"], 0.95)
        self.assertEqual(evaluation["models"]["hybrid"]["true_positives"], 50)
        self.assertLessEqual(evaluation["models"]["hybrid"]["false_positives"], 15)


class ApiSafetyTests(unittest.TestCase):
    def test_rate_limit_and_body_size_limit(self):
        test_app = FastAPI()
        test_app.add_middleware(main.ApiSafetyMiddleware, requests_per_window=1)

        @test_app.get("/api/test")
        def api_test():
            return {"status": "ok"}

        @test_app.post("/api/body")
        def read_body():
            return {"status": "ok"}

        with TestClient(test_app) as client:
            first = client.get("/api/test")
            limited = client.get("/api/test")
            oversized = client.post(
                "/api/body",
                content="x",
                headers={"Content-Length": str(main.MAX_REQUEST_BODY_BYTES + 1)},
            )

        self.assertEqual(first.status_code, 200)
        self.assertEqual(limited.status_code, 429)
        self.assertGreaterEqual(int(limited.headers["retry-after"]), 1)
        self.assertEqual(oversized.status_code, 413)

    def test_chunked_oversized_request_is_rejected(self):
        test_app = FastAPI()
        middleware = main.ApiSafetyMiddleware(test_app)
        chunks = [
            {
                "type": "http.request",
                "body": b"x" * main.MAX_REQUEST_BODY_BYTES,
                "more_body": True,
            },
            {"type": "http.request", "body": b"x", "more_body": False},
        ]
        responses = []

        async def receive():
            return chunks.pop(0)

        async def send(message):
            responses.append(message)

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/api/body",
            "headers": [],
            "client": ("127.0.0.1", 12345),
        }
        asyncio.run(middleware(scope, receive, send))

        self.assertEqual(responses[0]["status"], 413)


class TriageValidationTests(unittest.TestCase):
    def test_triage_schema_requires_three_remediation_steps(self):
        with self.assertRaisesRegex(ValueError, "exactly three"):
            LLMTriageService._validate_result(
                {
                    "tactic": "Exfiltration",
                    "severity": "critical",
                    "summary": "Possible data exfiltration detected.",
                    "remediation": ["Disconnect the host.", "Review data access."],
                }
            )

    def test_local_triage_does_not_call_normal_admin_traffic_brute_force(self):
        result = LLMTriageService()._mock_triage(
            {
                "dest_port": 22,
                "bytes_transferred": 2500,
                "failed_login_attempts": 0,
                "user_agent": "OpenSSH_9.6",
                "source_ip": "10.0.0.2",
                "dest_ip": "10.0.4.15",
            }
        )

        self.assertEqual(result["severity"], "MEDIUM")
        self.assertIn("Persistence", result["tactic"])
