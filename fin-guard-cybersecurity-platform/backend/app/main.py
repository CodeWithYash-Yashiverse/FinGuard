"""FinGuard FastAPI application.

Endpoints
---------
``POST /v1/analyze``
    Analyse a text message for digital-payment scam indicators.

``GET /health``
    Lightweight readiness probe.

The application never logs, persists, or returns raw message text.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .config import CORS_ORIGINS
from .detector import analyze_message
from .schemas import (
    MESSAGE_MAX_LENGTH,
    MESSAGE_MIN_LENGTH,
    AnalysisResult,
    AnalyzeRequest,
)

# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

app = FastAPI(
    title="FinGuard API",
    version="1.0.0",
    description="Explainable digital-payment scam-awareness API.",
    docs_url="/docs",
    redoc_url=None,
)

# CORS — allow the local Next.js frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["Content-Type"],
)

# ---------------------------------------------------------------------------
# Error helpers — match the frontend's ``ApiErrorBody`` shape:
#   { "error": { "code": "...", "message": "..." } }
# ---------------------------------------------------------------------------


def _error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": message}},
        headers={"Cache-Control": "no-store"},
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/health")
async def health() -> dict[str, str]:
    """Readiness probe.  Returns ``{"status": "ok"}``."""
    return {"status": "ok"}


@app.post(
    "/v1/analyze",
    response_model=AnalysisResult,
    response_model_by_alias=True,
)
async def analyze(request: Request) -> JSONResponse:
    """Analyse a message for scam indicators.

    Accepts ``{ "message": "..." }`` (and optional ``"source": "text"|"ocr"``).
    Returns an ``AnalysisResult`` with camelCase field names.
    """
    # --- Parse JSON body ---
    try:
        body = await request.json()
    except Exception:
        return _error(400, "invalid_json", "The request body must be valid JSON.")

    if not isinstance(body, dict):
        return _error(400, "invalid_json", "The request body must be a JSON object.")

    # --- Validate ``message`` field ---
    message = body.get("message")
    if not isinstance(message, str):
        return _error(
            400,
            "invalid_message",
            "Please provide the message text to analyze.",
        )

    trimmed = message.strip()

    if len(trimmed) < MESSAGE_MIN_LENGTH:
        return _error(
            400,
            "message_too_short",
            f"Please paste at least {MESSAGE_MIN_LENGTH} characters.",
        )

    if len(trimmed) > MESSAGE_MAX_LENGTH:
        return _error(
            413,
            "message_too_long",
            f"Messages are limited to {MESSAGE_MAX_LENGTH} characters.",
        )

    # --- Run detection ---
    result = analyze_message(trimmed)

    return JSONResponse(
        content=result.model_dump(by_alias=True),
        headers={"Cache-Control": "no-store"},
    )
