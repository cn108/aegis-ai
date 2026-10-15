import json
import logging
import sqlite3
from contextlib import asynccontextmanager, closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress

from api.detection import get_detector
from services.llm_triage import LLMTriageService

BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_PATH = BASE_DIR / "db.sqlite3"
logger = logging.getLogger(__name__)
triage_service = LLMTriageService()


class NetworkLog(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: datetime
    source_ip: IPvAnyAddress
    dest_ip: IPvAnyAddress
    dest_port: int = Field(ge=1, le=65535)
    protocol: str = Field(min_length=1, max_length=20)
    bytes_transferred: int = Field(ge=0)
    failed_login_attempts: int = Field(ge=0)
    user_agent: str = Field(min_length=1, max_length=1024)
    geo_location: str = Field(min_length=1, max_length=100)


class AlertResponse(BaseModel):
    id: int
    timestamp: str
    source_ip: str
    dest_ip: str
    dest_port: int
    anomaly_score: float
    tactic: str
    severity: str
    summary: str
    remediation: list[str]
    raw_log: dict[str, Any]
    created_at: str


class LogProcessingResult(BaseModel):
    is_anomaly: bool
    anomaly_score: float
    alert: AlertResponse | None


def get_connection():
    connection = sqlite3.connect(DATABASE_PATH, timeout=5)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with closing(get_connection()) as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS aegis_alerts (
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
            );
            CREATE INDEX IF NOT EXISTS aegis_alerts_created_at_idx
                ON aegis_alerts (created_at DESC);
            CREATE INDEX IF NOT EXISTS aegis_alerts_severity_idx
                ON aegis_alerts (severity);
            """
        )
        connection.commit()


def alert_from_row(row):
    alert = dict(row)
    alert["remediation"] = json.loads(alert["remediation"])
    alert["raw_log"] = json.loads(alert["raw_log"])
    return AlertResponse(**alert)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    initialize_database()
    yield


app = FastAPI(
    title="Aegis AI",
    description="Network anomaly detection and analyst-ready security triage.",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/logs/", response_model=LogProcessingResult)
def process_log(log: NetworkLog):
    raw_log = log.model_dump(mode="json")
    raw_log["source_ip"] = str(log.source_ip)
    raw_log["dest_ip"] = str(log.dest_ip)
    try:
        is_anomaly, anomaly_score = get_detector().score(raw_log)
    except FileNotFoundError as exc:
        logger.exception("Anomaly detection model artifacts are missing")
        raise HTTPException(status_code=503, detail="Anomaly detection model is not available.") from exc

    if not is_anomaly:
        return LogProcessingResult(is_anomaly=False, anomaly_score=anomaly_score, alert=None)

    try:
        triage = triage_service.triage_anomaly(raw_log)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail="Threat triage provider failed.") from exc

    created_at = datetime.now(timezone.utc).isoformat()
    with closing(get_connection()) as connection:
        cursor = connection.execute(
            """
            INSERT INTO aegis_alerts (
                timestamp, source_ip, dest_ip, dest_port, anomaly_score,
                tactic, severity, summary, remediation, raw_log, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                raw_log["timestamp"],
                raw_log["source_ip"],
                raw_log["dest_ip"],
                raw_log["dest_port"],
                anomaly_score,
                triage["tactic"],
                triage["severity"],
                triage["summary"],
                json.dumps(triage["remediation"]),
                json.dumps(raw_log),
                created_at,
            ),
        )
        connection.commit()
        row = connection.execute(
            "SELECT * FROM aegis_alerts WHERE id = ?", (cursor.lastrowid,)
        ).fetchone()

    return LogProcessingResult(
        is_anomaly=True,
        anomaly_score=anomaly_score,
        alert=alert_from_row(row),
    )


@app.get("/api/alerts/", response_model=list[AlertResponse])
def list_alerts(
    severity: str | None = Query(default=None, min_length=1, max_length=50),
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    query = "SELECT * FROM aegis_alerts"
    parameters: list[Any] = []
    if severity:
        query += " WHERE severity = ?"
        parameters.append(severity.upper())
    query += " ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
    parameters.extend([limit, offset])

    with closing(get_connection()) as connection:
        rows = connection.execute(query, parameters).fetchall()
    return [alert_from_row(row) for row in rows]
