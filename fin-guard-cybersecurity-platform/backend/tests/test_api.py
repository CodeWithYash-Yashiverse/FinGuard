"""API-level tests for the FinGuard FastAPI application.

Uses ``httpx.AsyncClient`` via ``pytest`` to test the full request/response
cycle without starting a real server.

Run from the ``backend/`` directory::

    python -m pytest tests/ -v
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.schemas import MESSAGE_MAX_LENGTH, MESSAGE_MIN_LENGTH


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def client():
    """Return an async httpx client wired to the FastAPI app."""
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://testserver")


# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------


class TestHealth:
    @pytest.mark.anyio
    async def test_health_returns_ok(self, client):
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# POST /v1/analyze — success cases
# ---------------------------------------------------------------------------


class TestAnalyzeSuccess:
    @pytest.mark.anyio
    async def test_valid_message_returns_200(self, client):
        resp = await client.post(
            "/v1/analyze",
            json={"message": "Please share your OTP 482913 to verify your account."},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["riskLevel"] in ("high_risk", "suspicious", "no_strong_signs")
        assert isinstance(data["summary"], str)
        assert isinstance(data["signals"], list)
        assert isinstance(data["nextSteps"], list)

    @pytest.mark.anyio
    async def test_response_uses_camel_case(self, client):
        resp = await client.post(
            "/v1/analyze",
            json={"message": "This is a simple test message for the API."},
        )
        assert resp.status_code == 200
        data = resp.json()
        # camelCase keys
        assert "riskLevel" in data
        assert "nextSteps" in data
        assert "analyzedAt" in data
        # snake_case must NOT appear
        assert "risk_level" not in data
        assert "next_steps" not in data
        assert "analyzed_at" not in data

    @pytest.mark.anyio
    async def test_cache_control_header(self, client):
        resp = await client.post(
            "/v1/analyze",
            json={"message": "Check the cache control headers on this response."},
        )
        assert resp.status_code == 200
        assert resp.headers.get("cache-control") == "no-store"

    @pytest.mark.anyio
    async def test_high_risk_message(self, client):
        resp = await client.post(
            "/v1/analyze",
            json={
                "message": (
                    "Dear customer, share your OTP 482913 immediately or your "
                    "SBI account will be blocked. Install AnyDesk now."
                )
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["riskLevel"] == "high_risk"
        assert len(data["signals"]) >= 1
        assert len(data["nextSteps"]) >= 1

    @pytest.mark.anyio
    async def test_safe_message(self, client):
        resp = await client.post(
            "/v1/analyze",
            json={"message": "Good morning, have a wonderful day ahead!"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["riskLevel"] == "no_strong_signs"
        assert data["signals"] == []

    @pytest.mark.anyio
    async def test_verification_field_present(self, client):
        resp = await client.post(
            "/v1/analyze",
            json={"message": "Please verify your account details."},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "verification" in data
        assert isinstance(data["verification"], list)
        assert len(data["verification"]) > 0

    @pytest.mark.anyio
    async def test_engine_info_present(self, client):
        resp = await client.post(
            "/v1/analyze",
            json={"message": "Testing engine info in the response."},
        )
        assert resp.status_code == 200
        engine = resp.json()["engine"]
        assert engine["name"] == "FinGuard heuristic engine"
        assert engine["version"] == "1.0.0"
        assert engine["mode"] == "local"

    @pytest.mark.anyio
    async def test_optional_source_field(self, client):
        """The ``source`` field is optional and should not affect the result."""
        resp = await client.post(
            "/v1/analyze",
            json={
                "message": "Testing with OCR source indicator field.",
                "source": "ocr",
            },
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# POST /v1/analyze — validation errors
# ---------------------------------------------------------------------------


class TestAnalyzeValidation:
    @pytest.mark.anyio
    async def test_empty_body(self, client):
        resp = await client.post(
            "/v1/analyze",
            content=b"",
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 400
        err = resp.json()["error"]
        assert err["code"] == "invalid_json"

    @pytest.mark.anyio
    async def test_invalid_json(self, client):
        resp = await client.post(
            "/v1/analyze",
            content=b"not json",
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == "invalid_json"

    @pytest.mark.anyio
    async def test_missing_message_field(self, client):
        resp = await client.post("/v1/analyze", json={"text": "oops wrong key"})
        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == "invalid_message"

    @pytest.mark.anyio
    async def test_message_not_string(self, client):
        resp = await client.post("/v1/analyze", json={"message": 12345})
        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == "invalid_message"

    @pytest.mark.anyio
    async def test_message_too_short(self, client):
        resp = await client.post("/v1/analyze", json={"message": "short"})
        assert resp.status_code == 400
        err = resp.json()["error"]
        assert err["code"] == "message_too_short"
        assert str(MESSAGE_MIN_LENGTH) in err["message"]

    @pytest.mark.anyio
    async def test_whitespace_only_message(self, client):
        resp = await client.post("/v1/analyze", json={"message": "      \t\n   "})
        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == "message_too_short"

    @pytest.mark.anyio
    async def test_message_too_long(self, client):
        resp = await client.post(
            "/v1/analyze",
            json={"message": "x" * (MESSAGE_MAX_LENGTH + 1)},
        )
        assert resp.status_code == 413
        assert resp.json()["error"]["code"] == "message_too_long"

    @pytest.mark.anyio
    async def test_message_at_min_boundary(self, client):
        """Exactly MESSAGE_MIN_LENGTH chars should be accepted."""
        resp = await client.post(
            "/v1/analyze",
            json={"message": "a" * MESSAGE_MIN_LENGTH},
        )
        assert resp.status_code == 200

    @pytest.mark.anyio
    async def test_message_at_max_boundary(self, client):
        """Exactly MESSAGE_MAX_LENGTH chars should be accepted."""
        resp = await client.post(
            "/v1/analyze",
            json={"message": "a" * MESSAGE_MAX_LENGTH},
        )
        assert resp.status_code == 200

    @pytest.mark.anyio
    async def test_non_object_json(self, client):
        """A JSON array or string should be rejected."""
        resp = await client.post(
            "/v1/analyze",
            content=b'["not", "an", "object"]',
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 400

    @pytest.mark.anyio
    async def test_error_response_shape(self, client):
        """All error responses must have { error: { code, message } }."""
        resp = await client.post("/v1/analyze", json={"message": "x"})
        assert resp.status_code == 400
        body = resp.json()
        assert "error" in body
        assert "code" in body["error"]
        assert "message" in body["error"]
        assert isinstance(body["error"]["code"], str)
        assert isinstance(body["error"]["message"], str)


# ---------------------------------------------------------------------------
# POST /v1/analyze — signal content checks via API
# ---------------------------------------------------------------------------


class TestAnalyzeSignals:
    @pytest.mark.anyio
    async def test_credential_request_via_api(self, client):
        resp = await client.post(
            "/v1/analyze",
            json={
                "message": "Please send your OTP 482913 to complete verification."
            },
        )
        data = resp.json()
        signal_ids = {s["id"] for s in data["signals"]}
        assert "credential-request" in signal_ids

    @pytest.mark.anyio
    async def test_otp_redacted_via_api(self, client):
        """Evidence returned through the API must have OTP digits masked."""
        resp = await client.post(
            "/v1/analyze",
            json={"message": "Share your OTP 847291 now to unlock your account."},
        )
        data = resp.json()
        for signal in data["signals"]:
            for evidence in signal["evidence"]:
                assert "847291" not in evidence

    @pytest.mark.anyio
    async def test_link_analysis_via_api(self, client):
        resp = await client.post(
            "/v1/analyze",
            json={
                "message": "Update your KYC now at http://sbi-kyc.xyz/update"
            },
        )
        data = resp.json()
        link_ids = {s["id"] for s in data["signals"] if s["category"] == "link"}
        assert len(link_ids) > 0

    @pytest.mark.anyio
    async def test_false_positive_negation_via_api(self, client):
        """'Do not share your OTP' must NOT trigger credential-request."""
        resp = await client.post(
            "/v1/analyze",
            json={
                "message": (
                    "Your OTP is 482913. Valid for 10 minutes. "
                    "Do not share this OTP with anyone. - HDFC Bank"
                )
            },
        )
        data = resp.json()
        signal_ids = {s["id"] for s in data["signals"]}
        assert "credential-request" not in signal_ids
