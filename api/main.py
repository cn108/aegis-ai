import json
import logging
import math
import os
import secrets
import sqlite3
import threading
import time
from contextlib import asynccontextmanager, closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress

from api.detection import get_detector
from services.llm_triage import LLMTriageService

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")
DATABASE_PATH = Path(os.environ.get("AEGIS_DATABASE_PATH", BASE_DIR / "db.sqlite3"))
API_AUTH_TOKEN = os.environ.get("AEGIS_API_TOKEN")
RATE_LIMIT_REQUESTS = int(os.environ.get("AEGIS_RATE_LIMIT_REQUESTS", "120"))
RATE_LIMIT_WINDOW_SECONDS = 60
MAX_REQUEST_BODY_BYTES = 1_048_576
logger = logging.getLogger(__name__)
triage_service = LLMTriageService()
bearer_scheme = HTTPBearer(auto_error=False)


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
    detection_methods: list[str]
    triage_source: str
    review_status: str
    reviewed_by: str | None
    review_note: str | None


class AlertsPage(BaseModel):
    items: list[AlertResponse]
    total: int
    limit: int
    offset: int


class ReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    review_status: Literal["pending_review", "confirmed", "false_positive", "escalated"]
    reviewer: str = Field(min_length=1, max_length=120)
    note: str | None = Field(default=None, max_length=2000)


class AuditEventResponse(BaseModel):
    id: int
    alert_id: int
    event_type: str
    actor: str
    details: dict[str, Any]
    created_at: str


class LogProcessingResult(BaseModel):
    is_anomaly: bool
    anomaly_score: float
    alert: AlertResponse | None


def get_connection():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
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
                created_at TEXT NOT NULL,
                detection_methods TEXT NOT NULL DEFAULT '[]',
                triage_source TEXT NOT NULL DEFAULT 'local',
                review_status TEXT NOT NULL DEFAULT 'pending_review',
                reviewed_by TEXT,
                review_note TEXT
            );
            CREATE TABLE IF NOT EXISTS aegis_audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER NOT NULL REFERENCES aegis_alerts(id),
                event_type TEXT NOT NULL,
                actor TEXT NOT NULL,
                details TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        existing_columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(aegis_alerts)").fetchall()
        }
        migrations = {
            "detection_methods": "TEXT NOT NULL DEFAULT '[]'",
            "triage_source": "TEXT NOT NULL DEFAULT 'local'",
            "review_status": "TEXT NOT NULL DEFAULT 'pending_review'",
            "reviewed_by": "TEXT",
            "review_note": "TEXT",
        }
        for column, definition in migrations.items():
            if column not in existing_columns:
                connection.execute(
                    f"ALTER TABLE aegis_alerts ADD COLUMN {column} {definition}"
                )
        connection.executescript(
            """
            CREATE INDEX IF NOT EXISTS aegis_alerts_created_at_idx
                ON aegis_alerts (created_at DESC);
            CREATE INDEX IF NOT EXISTS aegis_alerts_severity_idx
                ON aegis_alerts (severity);
            CREATE INDEX IF NOT EXISTS aegis_alerts_review_status_idx
                ON aegis_alerts (review_status);
            CREATE INDEX IF NOT EXISTS aegis_audit_alert_id_idx
                ON aegis_audit_events (alert_id, id);
            """
        )
        connection.commit()


def alert_from_row(row):
    alert = dict(row)
    alert["remediation"] = json.loads(alert["remediation"])
    alert["raw_log"] = json.loads(alert["raw_log"])
    alert["detection_methods"] = json.loads(alert["detection_methods"])
    return AlertResponse(**alert)


def require_api_token(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
):
    if not API_AUTH_TOKEN:
        raise HTTPException(
            status_code=503,
            detail="API authentication is not configured. Set AEGIS_API_TOKEN.",
        )
    if len(API_AUTH_TOKEN) < 32:
        raise HTTPException(
            status_code=503,
            detail="AEGIS_API_TOKEN must contain at least 32 characters.",
        )
    if credentials is None or not secrets.compare_digest(
        credentials.credentials, API_AUTH_TOKEN
    ):
        raise HTTPException(
            status_code=401,
            detail="A valid bearer token is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )


class ApiSafetyMiddleware:
    def __init__(self, app, requests_per_window=RATE_LIMIT_REQUESTS):
        self.app = app
        self.requests_per_window = requests_per_window
        self.request_times: dict[str, list[float]] = {}
        self.lock = threading.Lock()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not scope["path"].startswith("/api/"):
            await self.app(scope, receive, send)
            return

        headers = {
            key.lower(): value for key, value in scope.get("headers", [])
        }
        content_length = headers.get(b"content-length")
        if content_length:
            try:
                body_size = int(content_length)
            except ValueError:
                await self._reject(send, 400, "Invalid Content-Length header.")
                return
            if body_size < 0:
                await self._reject(send, 400, "Invalid Content-Length header.")
                return
            if body_size > MAX_REQUEST_BODY_BYTES:
                await self._reject(send, 413, "Request body exceeds the 1 MiB limit.")
                return

        if scope["method"] in {"POST", "PUT", "PATCH"}:
            chunks = []
            body_size = 0
            more_body = True
            while more_body:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                chunk = message.get("body", b"")
                body_size += len(chunk)
                if body_size > MAX_REQUEST_BODY_BYTES:
                    await self._reject(send, 413, "Request body exceeds the 1 MiB limit.")
                    return
                chunks.append(chunk)
                more_body = message.get("more_body", False)

            body = b"".join(chunks)
            replayed = False

            async def replay_body():
                nonlocal replayed
                if not replayed:
                    replayed = True
                    return {"type": "http.request", "body": body, "more_body": False}
                return await receive()

            receive = replay_body

        client = scope.get("client")
        client_ip = client[0] if client else "unknown"
        now = time.monotonic()
        retry_after = None
        with self.lock:
            recent_requests = [
                timestamp
                for timestamp in self.request_times.get(client_ip, [])
                if now - timestamp < RATE_LIMIT_WINDOW_SECONDS
            ]
            if len(recent_requests) >= self.requests_per_window:
                retry_after = max(
                    1,
                    math.ceil(
                        RATE_LIMIT_WINDOW_SECONDS - (now - recent_requests[0])
                    ),
                )
                self.request_times[client_ip] = recent_requests
            else:
                recent_requests.append(now)
                self.request_times[client_ip] = recent_requests
            if len(self.request_times) > 2048:
                self.request_times = {
                    ip: timestamps
                    for ip, timestamps in self.request_times.items()
                    if timestamps and now - timestamps[-1] < RATE_LIMIT_WINDOW_SECONDS
                }

        if retry_after is not None:
            await self._reject(
                send,
                429,
                "Request rate limit exceeded.",
                headers=[(b"retry-after", str(retry_after).encode("ascii"))],
            )
            return

        await self.app(scope, receive, send)

    @staticmethod
    async def _reject(send, status_code, detail, headers=None):
        body = json.dumps({"detail": detail}).encode("utf-8")
        response_headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
        ]
        response_headers.extend(headers or [])
        await send(
            {
                "type": "http.response.start",
                "status": status_code,
                "headers": response_headers,
            }
        )
        await send(
            {"type": "http.response.body", "body": body, "more_body": False}
        )


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
app.add_middleware(ApiSafetyMiddleware)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/dashboard", include_in_schema=False)
def dashboard():
    return FileResponse(BASE_DIR / "api" / "static" / "dashboard.html")


@app.post("/api/logs/", response_model=LogProcessingResult)
def process_log(log: NetworkLog, _auth=Depends(require_api_token)):
    raw_log = log.model_dump(mode="json")
    raw_log["source_ip"] = str(log.source_ip)
    raw_log["dest_ip"] = str(log.dest_ip)
    try:
        is_anomaly, anomaly_score, detection_methods = get_detector().score(raw_log)
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
                tactic, severity, summary, remediation, raw_log, created_at,
                detection_methods, triage_source, review_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending_review')
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
                json.dumps(detection_methods),
                triage_service.mode,
            ),
        )
        row = connection.execute(
            "SELECT * FROM aegis_alerts WHERE id = ?", (cursor.lastrowid,)
        ).fetchone()
        connection.execute(
            """
            INSERT INTO aegis_audit_events (alert_id, event_type, actor, details, created_at)
            VALUES (?, 'alert.created', 'system', ?, ?)
            """,
            (
                cursor.lastrowid,
                json.dumps(
                    {
                        "detection_methods": detection_methods,
                        "triage_source": triage_service.mode,
                    }
                ),
                created_at,
            ),
        )
        connection.commit()

    return LogProcessingResult(
        is_anomaly=True,
        anomaly_score=anomaly_score,
        alert=alert_from_row(row),
    )


@app.get("/api/alerts/", response_model=AlertsPage)
def list_alerts(
    severity: str | None = Query(default=None, min_length=1, max_length=50),
    review_status: str | None = Query(default=None, min_length=1, max_length=30),
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _auth=Depends(require_api_token),
) -> AlertsPage:
    query = "SELECT * FROM aegis_alerts"
    count_query = "SELECT COUNT(*) FROM aegis_alerts"
    parameters: list[Any] = []
    filters = []
    if severity:
        filters.append("severity = ?")
        parameters.append(severity.upper())
    if review_status:
        filters.append("review_status = ?")
        parameters.append(review_status)
    where_clause = " WHERE " + " AND ".join(filters) if filters else ""
    query += where_clause
    count_query += where_clause
    count_parameters = list(parameters)
    query += " ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
    parameters.extend([limit, offset])

    with closing(get_connection()) as connection:
        rows = connection.execute(query, parameters).fetchall()
        total = connection.execute(count_query, count_parameters).fetchone()[0]
    return AlertsPage(
        items=[alert_from_row(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@app.patch("/api/alerts/{alert_id}/review", response_model=AlertResponse)
def review_alert(
    alert_id: int,
    review: ReviewRequest,
    _auth=Depends(require_api_token),
):
    created_at = datetime.now(timezone.utc).isoformat()
    reviewer = review.reviewer.strip()
    if not reviewer:
        raise HTTPException(status_code=422, detail="Reviewer name cannot be blank.")
    note = review.note.strip() if review.note is not None else None
    with closing(get_connection()) as connection:
        current = connection.execute(
            "SELECT * FROM aegis_alerts WHERE id = ?", (alert_id,)
        ).fetchone()
        if current is None:
            raise HTTPException(status_code=404, detail="Alert not found.")
        previous_status = current["review_status"]
        connection.execute(
            """
            UPDATE aegis_alerts
            SET review_status = ?, reviewed_by = ?, review_note = ?
            WHERE id = ?
            """,
            (review.review_status, reviewer, note, alert_id),
        )
        connection.execute(
            """
            INSERT INTO aegis_audit_events (alert_id, event_type, actor, details, created_at)
            VALUES (?, 'alert.reviewed', ?, ?, ?)
            """,
            (
                alert_id,
                reviewer,
                json.dumps(
                    {
                        "previous_status": previous_status,
                        "review_status": review.review_status,
                        "note": note,
                    }
                ),
                created_at,
            ),
        )
        updated = connection.execute(
            "SELECT * FROM aegis_alerts WHERE id = ?", (alert_id,)
        ).fetchone()
        connection.commit()
    return alert_from_row(updated)


@app.get("/api/alerts/{alert_id}/history", response_model=list[AuditEventResponse])
def alert_history(alert_id: int, _auth=Depends(require_api_token)):
    with closing(get_connection()) as connection:
        exists = connection.execute(
            "SELECT 1 FROM aegis_alerts WHERE id = ?", (alert_id,)
        ).fetchone()
        if exists is None:
            raise HTTPException(status_code=404, detail="Alert not found.")
        rows = connection.execute(
            "SELECT * FROM aegis_audit_events WHERE alert_id = ? ORDER BY id",
            (alert_id,),
        ).fetchall()
    events = []
    for row in rows:
        event = dict(row)
        event["details"] = json.loads(event["details"])
        events.append(AuditEventResponse(**event))
    return events
