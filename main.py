"""
Daily Nutrition Tracker – FastAPI Backend
=========================================
Security notes:
  - All SQL queries use parameterized statements (no string concatenation).
  - Input is validated via Pydantic models with strict field constraints.
  - CORS is restricted to a configurable allow-list (no wildcard in production).
  - Generic error messages are returned to clients; details are logged server-side.
  - Security response headers (CSP, X-Content-Type-Options, X-Frame-Options,
    Permissions-Policy) are injected via middleware.
  - The SQLite file is local and not web-accessible.
TODO(security): Add authentication / API-key gate before exposing to the internet.
TODO(security): Enable HTTPS / TLS termination (e.g., via nginx) in production.
TODO(security): Rate-limit endpoints to prevent DoS / brute-force.
TODO(security): Consider migrating to a proper RDBMS with mTLS when scaling beyond
                a single Raspberry Pi.
TODO(security): Implement OAuth 2.0 / OpenID Connect for multi-user support.
"""

import logging
import os
import re
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional
from fastapi import FastAPI, HTTPException, Path, Request, Response
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator
# ---------------------------------------------------------------------------
# Logging – only safe, non-sensitive operational messages
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s – %(message)s",
)
logger = logging.getLogger("nutrition_tracker")
# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DB_PATH = os.environ.get("NUTRITION_DB_PATH", "nutrition.db")
# CORS: Restrict to explicit origins via env var (comma-separated), or allow any localhost port by default.
_raw_origins = os.environ.get("ALLOWED_ORIGINS")
if _raw_origins:
    ALLOWED_ORIGINS: list[str] = [o.strip() for o in _raw_origins.split(",") if o.strip()]
    ALLOW_ORIGIN_REGEX: Optional[str] = None
else:
    ALLOWED_ORIGINS = []
    ALLOW_ORIGIN_REGEX = r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$"

# Content Security Policy for HTML/static responses
HTML_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-eval' https://cdn.jsdelivr.net 'sha256-/BnQq/ydob9c0+UT8rtZ4QjtLxIFL9o8n0oUeeXRzSE='; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "
    "font-src 'self' https://fonts.gstatic.com; "
    "connect-src 'self' http: https:; "
    "img-src 'self' data:; "
    "object-src 'none'; "
    "frame-ancestors 'none';"
)
# Allow-list of valid food categories
VALID_CATEGORIES = frozenset(
    ["主餐", "雞胸肉", "蛋餅", "蛋", "三角飯糰", "豆漿", "豆製品", "少肉餐點", "其他"]
)
PROTEIN_COEFFICIENTS: dict[str, float] = {
    "主餐": 25.0,
    "雞胸肉": 25.0,
    "蛋餅": 25.0,
    "蛋": 7.0,
    "三角飯糰": 6.0,
    "豆漿": 15.0,
    "豆製品": 10.0,
    "少肉餐點": 10.0,
    "其他": 1.0,
}
# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
def get_db() -> sqlite3.Connection:
    """Return a new SQLite connection with row_factory for dict-like access."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn
def init_db() -> None:
    """Create tables if they do not already exist."""
    with get_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS food_logs (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                category  TEXT    NOT NULL,
                quantity  REAL    NOT NULL,
                protein_g REAL    NOT NULL,
                note      TEXT,
                logged_at TEXT    NOT NULL
            )
            """
        )
        conn.commit()
    logger.info("Database initialised at %s", DB_PATH)
# ---------------------------------------------------------------------------
# Application lifespan
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield
# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Daily Nutrition Tracker API",
    description="Track daily food and protein intake.",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url=None,
)
# ---------------------------------------------------------------------------
# CORS middleware – explicit origin allow-list, no wildcard
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=ALLOW_ORIGIN_REGEX,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Accept"],
    max_age=600,
)
# ---------------------------------------------------------------------------
# Security headers middleware
# ---------------------------------------------------------------------------
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.url.path.startswith("/api/") or request.url.path == "/health":
        response.headers["Content-Security-Policy"] = "default-src 'none'"
    else:
        response.headers["Content-Security-Policy"] = HTML_CSP
    return response
# ---------------------------------------------------------------------------
# Frontend & Static file routes (Explicitly served for security)
# ---------------------------------------------------------------------------
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/", include_in_schema=False)
@app.get("/index.html", include_in_schema=False)
def serve_index():
    return FileResponse("index.html")

@app.get("/favicon.ico", include_in_schema=False)
def serve_favicon():
    return FileResponse("static/favicon/favicon.ico")

@app.get("/manifest.json", include_in_schema=False)
def serve_manifest():
    return FileResponse("manifest.json", media_type="application/manifest+json")

@app.get("/sw.js", include_in_schema=False)
def serve_sw():
    return FileResponse("sw.js", media_type="application/javascript")

@app.get("/tailwindcss.js", include_in_schema=False)
def serve_tailwindcss():
    return FileResponse("tailwindcss.js", media_type="application/javascript")
# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------
class FoodLogCreate(BaseModel):
    """Validated request body for creating a food log entry."""
    category: str = Field(..., min_length=1, max_length=50)
    quantity: float = Field(..., gt=0, le=9999)
    note: Optional[str] = Field(default=None, max_length=200)
    logged_date: Optional[str] = Field(
        default=None,
        description="Optional date override for make-up logging (YYYY-MM-DD). "
                    "Must be today or in the past (up to 90 days ago). "
                    "Defaults to current UTC date when omitted.",
    )
    @field_validator("category")
    @classmethod
    def validate_category(cls, v: str) -> str:
        if v not in VALID_CATEGORIES:
            raise ValueError(
                f"Invalid category. Must be one of: {', '.join(sorted(VALID_CATEGORIES))}"
            )
        return v
    @field_validator("note")
    @classmethod
    def sanitize_note(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        # Strip control characters; allow safe printable characters only
        sanitized = re.sub(r"[\x00-\x1f\x7f]", "", v).strip()
        return sanitized if sanitized else None
    @field_validator("logged_date")
    @classmethod
    def validate_logged_date(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        try:
            target = datetime.strptime(v, "%Y-%m-%d").date()
        except ValueError:
            raise ValueError("logged_date must be in YYYY-MM-DD format.")
        today = datetime.now(timezone.utc).date()
        if target > today:
            raise ValueError("logged_date cannot be in the future.")
        max_past = today.__class__.fromordinal(today.toordinal() - 90)
        if target < max_past:
            raise ValueError("logged_date cannot be more than 90 days in the past.")
        return v
# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.get("/api/logs", summary="List food logs")
def get_logs(date_filter: Optional[str] = None):
    """
    Return food log entries.  If `date_filter` is provided (YYYY-MM-DD), only
    entries from that day are returned.  Otherwise all entries are returned.
    """
    if date_filter is not None:
        try:
            datetime.strptime(date_filter, "%Y-%m-%d")
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD.")
    try:
        with get_db() as conn:
            if date_filter:
                rows = conn.execute(
                    "SELECT * FROM food_logs WHERE logged_at LIKE ? ORDER BY logged_at DESC",
                    (f"{date_filter}%",),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM food_logs ORDER BY logged_at DESC"
                ).fetchall()
    except sqlite3.Error:
        logger.exception("Database error in get_logs")
        raise HTTPException(status_code=500, detail="Could not retrieve logs.")
    return [dict(row) for row in rows]
@app.get("/api/logs/summary", summary="Per-day protein summary")
def get_summary():
    """Return total protein per day for the past 30 days."""
    try:
        with get_db() as conn:
            rows = conn.execute(
                """
                SELECT
                    substr(logged_at, 1, 10) AS day,
                    SUM(protein_g)           AS total_protein
                FROM food_logs
                WHERE logged_at >= date('now', '-30 days')
                GROUP BY day
                ORDER BY day DESC
                """
            ).fetchall()
    except sqlite3.Error:
        logger.exception("Database error in get_summary")
        raise HTTPException(status_code=500, detail="Could not retrieve summary.")
    return [dict(row) for row in rows]
@app.post("/api/logs", status_code=201, summary="Add a food log entry")
def create_log(body: FoodLogCreate):
    """Create a new food log entry.  Protein is calculated server-side.

    If `logged_date` is provided (YYYY-MM-DD, today or up to 90 days in the
    past), the entry is recorded at noon UTC on that date to support make-up
    logging for previous days.  Otherwise the current UTC timestamp is used.
    """
    protein_g = round(PROTEIN_COEFFICIENTS[body.category] * body.quantity, 2)
    if body.logged_date:
        # Set timestamp to noon UTC on the specified date so that the
        # date_filter LIKE query still matches correctly.
        logged_at = f"{body.logged_date}T12:00:00Z"
    else:
        logged_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        with get_db() as conn:
            cursor = conn.execute(
                """
                INSERT INTO food_logs (category, quantity, protein_g, note, logged_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (body.category, body.quantity, protein_g, body.note, logged_at),
            )
            conn.commit()
            new_id = cursor.lastrowid
    except sqlite3.Error:
        logger.exception("Database error in create_log")
        raise HTTPException(status_code=500, detail="Could not save log entry.")
    logger.info("Log entry created id=%s category=%s date=%s", new_id, body.category, body.logged_date or "now")
    return {
        "id": new_id,
        "category": body.category,
        "quantity": body.quantity,
        "protein_g": protein_g,
        "note": body.note,
        "logged_at": logged_at,
    }
@app.delete("/api/logs/{log_id}", status_code=200, summary="Delete a food log entry")
def delete_log(
    log_id: int = Path(..., gt=0, description="ID of the log entry to delete"),
):
    """Delete a food log entry by ID."""
    try:
        with get_db() as conn:
            result = conn.execute(
                "DELETE FROM food_logs WHERE id = ?",
                (log_id,),
            )
            conn.commit()
            if result.rowcount == 0:
                raise HTTPException(status_code=404, detail="Log entry not found.")
    except HTTPException:
        raise
    except sqlite3.Error:
        logger.exception("Database error in delete_log id=%s", log_id)
        raise HTTPException(status_code=500, detail="Could not delete log entry.")
    logger.info("Log entry deleted id=%s", log_id)
    return {"detail": "Deleted successfully."}
@app.get("/health", include_in_schema=False)
def health():
    return {"status": "ok"}
