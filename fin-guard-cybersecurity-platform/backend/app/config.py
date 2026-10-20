"""Environment-based configuration for the FinGuard backend.

All settings are read from environment variables prefixed with ``FINGUARD_``.
Defaults are safe for local development.
"""

from __future__ import annotations

import os

CORS_ORIGINS: list[str] = [
    origin.strip()
    for origin in os.getenv(
        "FINGUARD_CORS_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000",
    ).split(",")
    if origin.strip()
]

LOG_LEVEL: str = os.getenv("FINGUARD_LOG_LEVEL", "INFO")
