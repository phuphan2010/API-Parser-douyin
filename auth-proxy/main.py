"""
API Auth Proxy — FastAPI service
================================
Validates API keys, enforces rate limits, and proxies requests
to the upstream douyin/tiktok API service.

Features:
  - API Key authentication (X-API-Key header or ?api_key= query param)
  - Rate limiting: 100 requests/hour per key (configurable)
  - Key expiry: 30 days (configurable)
  - Admin endpoints for key management
  - SQLite storage (persistent via Docker volume)
  - Zero external dependencies beyond pip packages
"""

import os
import sqlite3
import secrets
import logging
from datetime import datetime, timezone, timedelta
from contextlib import asynccontextmanager
from typing import Optional

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel

# ── Configuration (via environment variables) ────────────────────────────────
DB_PATH            = os.environ.get("DB_PATH", "/app/data/keys.db")
ADMIN_SECRET       = os.environ.get("ADMIN_SECRET", "")
TARGET_URL         = os.environ.get("TARGET_URL", "http://douyin-api:80").rstrip("/")
RATE_LIMIT_PER_HOUR = int(os.environ.get("RATE_LIMIT_PER_HOUR", "100"))
KEY_EXPIRY_DAYS    = int(os.environ.get("KEY_EXPIRY_DAYS", "30"))
LOG_LEVEL          = os.environ.get("LOG_LEVEL", "INFO").upper()

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("auth-proxy")

# ── Headers that must NOT be forwarded to upstream ───────────────────────────
HOP_BY_HOP = frozenset({
    "host", "connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailers", "transfer-encoding",
    "upgrade", "x-api-key",
})

# ── Database helpers ─────────────────────────────────────────────────────────

def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # better concurrency
    return conn


def init_db() -> None:
    """Create tables and clean up stale rate-limit windows on startup."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS api_keys (
                key        TEXT PRIMARY KEY,
                name       TEXT NOT NULL,
                note       TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                enabled    INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS rate_limits (
                key          TEXT NOT NULL,
                window_start TEXT NOT NULL,
                count        INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (key, window_start)
            );
        """)
        # Remove rate-limit rows older than 48 h (they're useless)
        cutoff = (
            datetime.now(timezone.utc) - timedelta(hours=48)
        ).strftime("%Y-%m-%dT%H:00:00Z")
        conn.execute("DELETE FROM rate_limits WHERE window_start < ?", (cutoff,))
    logger.info("Database initialised at %s", DB_PATH)


# ── FastAPI app ───────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    if not ADMIN_SECRET:
        logger.critical("ADMIN_SECRET environment variable is not set! Admin endpoints are disabled.")
    init_db()
    logger.info("Auth Proxy started → forwarding to %s", TARGET_URL)
    logger.info("Rate limit: %d req/hour | Key expiry: %d days", RATE_LIMIT_PER_HOUR, KEY_EXPIRY_DAYS)
    yield
    logger.info("Auth Proxy shutting down.")


app = FastAPI(
    title="API Auth Proxy",
    description=(
        "API Key authentication gateway for the douyin/tiktok download API.\n\n"
        "**Pass your key via:** `X-API-Key` header  _or_  `?api_key=` query param.\n\n"
        "Admin endpoints require the `X-Admin-Secret` header."
    ),
    version="1.0.0",
    docs_url="/admin/docs",
    redoc_url="/admin/redoc",
    lifespan=lifespan,
)


# ── Utility functions ────────────────────────────────────────────────────────

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def current_hour_window() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:00:00Z")


def require_admin(x_admin_secret: str = Header(..., description="Admin secret from ADMIN_SECRET env var")) -> None:
    """FastAPI dependency — validates the admin secret header."""
    if not ADMIN_SECRET:
        raise HTTPException(503, "Admin secret not configured on server.")
    if x_admin_secret != ADMIN_SECRET:
        raise HTTPException(401, "Invalid admin secret.")


def _validate_and_rate_limit(api_key: str) -> dict:
    """
    Validate key existence, enabled state, expiry, and rate limit.
    Increments the counter atomically on success.
    Returns info dict with remaining quota.
    Raises HTTPException on any failure.
    """
    with get_db() as conn:
        row = conn.execute(
            "SELECT key, name, enabled, expires_at FROM api_keys WHERE key = ?",
            (api_key,)
        ).fetchone()

        if not row:
            logger.warning("Rejected request: unknown key …%s", api_key[-8:])
            raise HTTPException(401, "Invalid API key.")

        if not row["enabled"]:
            logger.warning("Rejected request: disabled key '%s'", row["name"])
            raise HTTPException(403, "API key is disabled.")

        if now_iso() > row["expires_at"]:
            logger.warning("Rejected request: expired key '%s' (expired %s)", row["name"], row["expires_at"])
            raise HTTPException(
                403,
                f"API key expired on {row['expires_at'][:10]}. "
                "Contact the admin to renew your key."
            )

        window = current_hour_window()
        rl_row = conn.execute(
            "SELECT count FROM rate_limits WHERE key = ? AND window_start = ?",
            (api_key, window),
        ).fetchone()
        count = rl_row["count"] if rl_row else 0

        if count >= RATE_LIMIT_PER_HOUR:
            logger.warning("Rate limit hit for key '%s' (%d/%d this hour)", row["name"], count, RATE_LIMIT_PER_HOUR)
            raise HTTPException(
                status_code=429,
                detail=(
                    f"Rate limit exceeded: {count}/{RATE_LIMIT_PER_HOUR} requests this hour. "
                    "Please retry after the hour resets."
                ),
                headers={
                    "Retry-After": "3600",
                    "X-RateLimit-Limit": str(RATE_LIMIT_PER_HOUR),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": window,
                },
            )

        # Atomic upsert
        conn.execute(
            """
            INSERT INTO rate_limits (key, window_start, count) VALUES (?, ?, 1)
            ON CONFLICT(key, window_start) DO UPDATE SET count = count + 1
            """,
            (api_key, window),
        )

    remaining = max(0, RATE_LIMIT_PER_HOUR - count - 1)
    return {"name": row["name"], "remaining": remaining}


# ── System endpoints ─────────────────────────────────────────────────────────

@app.get(
    "/health",
    tags=["System"],
    summary="Health check (no auth required)",
)
async def health():
    return {"status": "ok", "service": "api-auth-proxy", "version": "1.0.0"}


# ── Admin: Key Management ────────────────────────────────────────────────────

class CreateKeyRequest(BaseModel):
    name: str
    note: Optional[str] = ""


@app.get(
    "/admin/keys",
    tags=["Admin"],
    summary="List all API keys",
    dependencies=[Depends(require_admin)],
)
async def list_keys():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT key, name, note, created_at, expires_at, enabled "
            "FROM api_keys ORDER BY created_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


@app.post(
    "/admin/keys",
    tags=["Admin"],
    summary="Create a new API key",
    status_code=201,
    dependencies=[Depends(require_admin)],
)
async def create_key(body: CreateKeyRequest):
    key       = "ag_" + secrets.token_hex(24)   # e.g. ag_a1b2c3...
    now       = now_iso()
    expires   = (
        datetime.now(timezone.utc) + timedelta(days=KEY_EXPIRY_DAYS)
    ).isoformat(timespec="seconds")

    with get_db() as conn:
        conn.execute(
            "INSERT INTO api_keys (key, name, note, created_at, expires_at, enabled) "
            "VALUES (?, ?, ?, ?, ?, 1)",
            (key, body.name, body.note or "", now, expires),
        )

    logger.info("Created key '%s' (expires %s)", body.name, expires[:10])
    return {
        "key": key,
        "name": body.name,
        "note": body.note,
        "created_at": now,
        "expires_at": expires,
        "enabled": True,
    }


@app.delete(
    "/admin/keys/{key}",
    tags=["Admin"],
    summary="Delete an API key permanently",
    dependencies=[Depends(require_admin)],
)
async def delete_key(key: str):
    with get_db() as conn:
        r = conn.execute("DELETE FROM api_keys WHERE key = ?", (key,))
        if r.rowcount == 0:
            raise HTTPException(404, "Key not found.")
        conn.execute("DELETE FROM rate_limits WHERE key = ?", (key,))
    logger.info("Deleted key …%s", key[-8:])
    return {"message": "Key deleted."}


@app.patch(
    "/admin/keys/{key}/disable",
    tags=["Admin"],
    summary="Temporarily disable a key (reversible)",
    dependencies=[Depends(require_admin)],
)
async def disable_key(key: str):
    with get_db() as conn:
        r = conn.execute("UPDATE api_keys SET enabled = 0 WHERE key = ?", (key,))
        if r.rowcount == 0:
            raise HTTPException(404, "Key not found.")
    logger.info("Disabled key …%s", key[-8:])
    return {"message": "Key disabled."}


@app.patch(
    "/admin/keys/{key}/enable",
    tags=["Admin"],
    summary="Re-enable a previously disabled key",
    dependencies=[Depends(require_admin)],
)
async def enable_key(key: str):
    with get_db() as conn:
        r = conn.execute("UPDATE api_keys SET enabled = 1 WHERE key = ?", (key,))
        if r.rowcount == 0:
            raise HTTPException(404, "Key not found.")
    logger.info("Enabled key …%s", key[-8:])
    return {"message": "Key enabled."}


@app.post(
    "/admin/keys/{key}/renew",
    tags=["Admin"],
    summary=f"Renew a key's expiry by {KEY_EXPIRY_DAYS} days from now",
    dependencies=[Depends(require_admin)],
)
async def renew_key(key: str):
    new_expires = (
        datetime.now(timezone.utc) + timedelta(days=KEY_EXPIRY_DAYS)
    ).isoformat(timespec="seconds")
    with get_db() as conn:
        r = conn.execute(
            "UPDATE api_keys SET expires_at = ? WHERE key = ?", (new_expires, key)
        )
        if r.rowcount == 0:
            raise HTTPException(404, "Key not found.")
    logger.info("Renewed key …%s → expires %s", key[-8:], new_expires[:10])
    return {"message": "Key renewed.", "expires_at": new_expires}


@app.get(
    "/admin/stats",
    tags=["Admin"],
    summary="Usage statistics for this hour and key counts",
    dependencies=[Depends(require_admin)],
)
async def stats():
    window = current_hour_window()
    now    = now_iso()
    with get_db() as conn:
        total    = conn.execute("SELECT COUNT(*) FROM api_keys").fetchone()[0]
        active   = conn.execute("SELECT COUNT(*) FROM api_keys WHERE enabled = 1 AND expires_at > ?", (now,)).fetchone()[0]
        disabled = conn.execute("SELECT COUNT(*) FROM api_keys WHERE enabled = 0").fetchone()[0]
        expired  = conn.execute("SELECT COUNT(*) FROM api_keys WHERE expires_at <= ?", (now,)).fetchone()[0]
        this_hour = conn.execute(
            "SELECT COALESCE(SUM(count), 0) FROM rate_limits WHERE window_start = ?", (window,)
        ).fetchone()[0]
        top_keys = conn.execute(
            """
            SELECT k.name, rl.count
            FROM rate_limits rl
            JOIN api_keys k ON k.key = rl.key
            WHERE rl.window_start = ?
            ORDER BY rl.count DESC LIMIT 10
            """,
            (window,),
        ).fetchall()

    return {
        "current_window": window,
        "requests_this_hour": this_hour,
        "rate_limit_per_hour": RATE_LIMIT_PER_HOUR,
        "key_expiry_days": KEY_EXPIRY_DAYS,
        "keys": {
            "total": total,
            "active": active,
            "disabled": disabled,
            "expired": expired,
        },
        "top_consumers_this_hour": [dict(r) for r in top_keys],
    }


# ── Proxy catch-all ───────────────────────────────────────────────────────────

@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
    include_in_schema=False,  # Don't pollute Swagger with the wildcard route
)
async def proxy(request: Request, path: str):
    """
    Validates the API key, then transparently proxies the request
    to the upstream douyin-api service.
    """
    # Extract API key from header or query param
    api_key = (
        request.headers.get("X-API-Key")
        or request.query_params.get("api_key")
    )
    if not api_key:
        raise HTTPException(
            401,
            detail=(
                "API key required. "
                "Pass via 'X-API-Key' header or '?api_key=' query parameter."
            ),
        )

    info = _validate_and_rate_limit(api_key)

    # Build upstream URL — strip api_key from query params
    params = {k: v for k, v in request.query_params.items() if k != "api_key"}
    target = f"{TARGET_URL}/{path}"

    # Filter hop-by-hop headers before forwarding
    forward_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in HOP_BY_HOP
    }

    body = await request.body()

    logger.debug("→ %s %s (key: '%s')", request.method, target, info["name"])

    async with httpx.AsyncClient(timeout=60.0, follow_redirects=True) as client:
        upstream = await client.request(
            method=request.method,
            url=target,
            params=params,
            headers=forward_headers,
            content=body,
        )

    # Build response headers — strip problematic upstream headers
    resp_headers = {
        k: v for k, v in upstream.headers.items()
        if k.lower() not in {"transfer-encoding", "content-encoding", "connection", "server"}
    }
    resp_headers.update({
        "X-RateLimit-Limit":     str(RATE_LIMIT_PER_HOUR),
        "X-RateLimit-Remaining": str(info["remaining"]),
        "X-Served-By":           "api-auth-proxy",
    })

    logger.debug(
        "← %d from upstream (key: '%s', remaining: %d/hr)",
        upstream.status_code, info["name"], info["remaining"],
    )

    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        headers=resp_headers,
        media_type=upstream.headers.get("content-type"),
    )
