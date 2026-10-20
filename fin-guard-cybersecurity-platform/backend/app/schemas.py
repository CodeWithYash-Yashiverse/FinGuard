"""Pydantic models matching the TypeScript ``AnalysisResult`` contract.

Field names use **snake_case** in Python.  The ``alias_generator`` produces
**camelCase** aliases so that JSON responses are compatible with the existing
Next.js frontend (``riskLevel``, ``nextSteps``, ``analyzedAt``, etc.).

Source of truth: ``lib/analysis/types.ts`` in the frontend workspace.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel


# ---------------------------------------------------------------------------
# Enums — values must match the TypeScript union types exactly.
# ---------------------------------------------------------------------------

class RiskLevel(str, Enum):
    """Allowed risk-level values.

    Frontend reference: ``type RiskLevel = 'high_risk' | 'suspicious' | 'no_strong_signs'``
    """

    HIGH_RISK = "high_risk"
    SUSPICIOUS = "suspicious"
    NO_STRONG_SIGNS = "no_strong_signs"


class Severity(str, Enum):
    """Signal severity.

    Frontend reference: ``type Severity = 'high' | 'medium' | 'low'``
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class SignalCategory(str, Enum):
    """Detection-rule category.

    Frontend reference:
    ``type SignalCategory = 'link' | 'urgency' | 'credentials' | 'impersonation' | 'payment' | 'pattern'``
    """

    LINK = "link"
    URGENCY = "urgency"
    CREDENTIALS = "credentials"
    IMPERSONATION = "impersonation"
    PAYMENT = "payment"
    PATTERN = "pattern"


# ---------------------------------------------------------------------------
# Shared base with camelCase alias generation.
# ---------------------------------------------------------------------------

class _CamelModel(BaseModel):
    """Base model that serialises field names to camelCase."""

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
    )


# ---------------------------------------------------------------------------
# Response models — must match the TS ``AnalysisResult`` interface.
# ---------------------------------------------------------------------------

class WarningSignal(_CamelModel):
    """A single warning indicator with evidence.

    Frontend reference::

        interface WarningSignal {
          id: string
          category: SignalCategory
          title: string
          severity: Severity
          explanation: string
          evidence: string[]      // array of text excerpts
        }
    """

    id: str
    category: SignalCategory
    title: str
    severity: Severity
    explanation: str
    evidence: list[str]


class AnalysisEngineInfo(_CamelModel):
    """Metadata about the engine that produced the result.

    Frontend reference::

        interface AnalysisEngineInfo {
          name: string
          version: string
          mode: 'local' | 'remote'
        }
    """

    name: str
    version: str
    mode: Literal["local", "remote"]


class AnalysisResult(_CamelModel):
    """Complete analysis result returned by the API.

    Frontend reference::

        interface AnalysisResult {
          riskLevel: RiskLevel        // → risk_level
          summary: string
          signals: WarningSignal[]
          nextSteps: string[]         // → next_steps
          verification: string[]
          engine: AnalysisEngineInfo
          analyzedAt: string          // → analyzed_at  (ISO 8601)
        }
    """

    risk_level: RiskLevel
    summary: str
    signals: list[WarningSignal]
    next_steps: list[str]
    verification: list[str]
    engine: AnalysisEngineInfo
    analyzed_at: str


# ---------------------------------------------------------------------------
# Request model
# ---------------------------------------------------------------------------

class AnalyzeRequest(_CamelModel):
    """Incoming analysis request body.

    Frontend reference::

        interface AnalyzeRequest {
          message: string
          source?: 'text' | 'ocr'
        }
    """

    message: str
    source: Literal["text", "ocr"] = "text"


# ---------------------------------------------------------------------------
# Constants — must match TypeScript originals.
# ---------------------------------------------------------------------------

MESSAGE_MIN_LENGTH: int = 10
MESSAGE_MAX_LENGTH: int = 5000
