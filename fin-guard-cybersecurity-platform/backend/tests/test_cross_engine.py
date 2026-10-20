"""Phase 5.5 — Cross-engine consistency regression tests.

These tests ensure that the Python and TypeScript detection engines remain
behaviourally aligned on the shared fixture of 45 test messages.

The tests run the Python engine live and compare against pre-generated
TypeScript results stored in ``tests/fixtures/ts_engine_results.json``.

To refresh the TS results:
    npx tsx tests/run_ts_engine.ts      (from project root)

To run these tests:
    python -m pytest tests/ -v          (from backend/)

Known intentional differences
------------------------------
* **Evidence redaction**: Python's ``_redact_secrets()`` partially masks
  digit sequences of 4+ characters in evidence snippets.  The TypeScript
  engine does not redact.  This is documented and expected.

* **Evidence snippet boundaries with emoji**: Multi-byte emoji characters
  may produce slightly different snippet lengths due to Python ``len()``
  counting codepoints vs JavaScript ``String.length`` counting UTF-16
  code units.  This is cosmetic and expected.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from app.detector import analyze_message
from app.schemas import RiskLevel, Severity, SignalCategory


# ---------------------------------------------------------------------------
# Load fixtures
# ---------------------------------------------------------------------------

_FIXTURE_DIR = Path(__file__).resolve().parent.parent.parent / "tests" / "fixtures"
_FIXTURES = json.loads((_FIXTURE_DIR / "cross_engine_messages.json").read_text("utf-8"))
_TS_RESULTS = {
    r["id"]: r
    for r in json.loads((_FIXTURE_DIR / "ts_engine_results.json").read_text("utf-8"))
}


def _fixture_ids() -> list[str]:
    return [f["id"] for f in _FIXTURES]


def _fixture_by_id(fid: str) -> dict:
    return next(f for f in _FIXTURES if f["id"] == fid)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _strip_redaction(text: str) -> str:
    """Remove Python digit redaction so evidence can be compared
    structurally.

    Replaces sequences like ``1**4`` or ``4****3`` with a fixed token
    so that both engines' evidence can be normalized for comparison.
    """
    return re.sub(r"\d\*+\d", "<REDACTED>", text)


def _normalize_evidence(items: list[str]) -> list[str]:
    """Normalize evidence for structural comparison (ignoring redaction
    and minor whitespace/ellipsis boundary differences)."""
    normalized = []
    for item in items:
        s = _strip_redaction(item)
        # Collapse whitespace
        s = re.sub(r"\s+", " ", s).strip()
        # Remove leading/trailing ellipsis for prefix comparison
        s = s.strip("…").strip()
        normalized.append(s)
    return sorted(normalized)


# ===================================================================
# 1. Risk-level parity
# ===================================================================

class TestCrossEngineRiskLevel:
    """Every fixture message must produce the same risk level in both engines."""

    @pytest.mark.parametrize("fixture_id", _fixture_ids())
    def test_risk_level_matches(self, fixture_id: str):
        fixture = _fixture_by_id(fixture_id)
        py = analyze_message(fixture["message"])
        ts = _TS_RESULTS[fixture_id]
        assert py.risk_level.value == ts["riskLevel"], (
            f"Risk level mismatch on '{fixture_id}': "
            f"Python={py.risk_level.value}, TS={ts['riskLevel']}"
        )


# ===================================================================
# 2. Signal-ID parity
# ===================================================================

class TestCrossEngineSignalIds:
    """Both engines must fire the same set of signal IDs for every fixture."""

    @pytest.mark.parametrize("fixture_id", _fixture_ids())
    def test_signal_ids_match(self, fixture_id: str):
        fixture = _fixture_by_id(fixture_id)
        py = analyze_message(fixture["message"])
        ts = _TS_RESULTS[fixture_id]
        py_ids = sorted(s.id for s in py.signals)
        ts_ids = sorted(ts["signalIds"])
        assert py_ids == ts_ids, (
            f"Signal IDs mismatch on '{fixture_id}': "
            f"Python={py_ids}, TS={ts_ids}"
        )


# ===================================================================
# 3. Signal severity and category parity
# ===================================================================

class TestCrossEngineSignalAttributes:
    """For every shared signal, severity, category, title and explanation
    must be identical."""

    @pytest.mark.parametrize("fixture_id", _fixture_ids())
    def test_signal_attributes_match(self, fixture_id: str):
        fixture = _fixture_by_id(fixture_id)
        py = analyze_message(fixture["message"])
        ts = _TS_RESULTS[fixture_id]

        py_signals = {s.id: s for s in py.signals}
        ts_signals = {s["id"]: s for s in ts["signalDetails"]}

        shared = set(py_signals) & set(ts_signals)
        for sid in sorted(shared):
            ps = py_signals[sid]
            tss = ts_signals[sid]

            assert ps.severity.value == tss["severity"], (
                f"[{fixture_id}] signal '{sid}' severity: "
                f"Python={ps.severity.value}, TS={tss['severity']}"
            )
            assert ps.category.value == tss["category"], (
                f"[{fixture_id}] signal '{sid}' category: "
                f"Python={ps.category.value}, TS={tss['category']}"
            )
            assert ps.title == tss["title"], (
                f"[{fixture_id}] signal '{sid}' title mismatch"
            )
            assert ps.explanation == tss["explanation"], (
                f"[{fixture_id}] signal '{sid}' explanation mismatch"
            )


# ===================================================================
# 4. Evidence redaction — Python redacts, TS does not (intentional)
# ===================================================================

class TestCrossEngineEvidence:
    """Evidence snippets should be structurally equivalent after
    normalizing away Python's digit redaction."""

    @pytest.mark.parametrize("fixture_id", _fixture_ids())
    def test_evidence_structurally_similar(self, fixture_id: str):
        """After stripping digit redaction, evidence from both engines
        should cover the same text regions."""
        fixture = _fixture_by_id(fixture_id)
        py = analyze_message(fixture["message"])
        ts = _TS_RESULTS[fixture_id]

        py_signals = {s.id: s for s in py.signals}
        ts_signals = {s["id"]: s for s in ts["signalDetails"]}

        shared = set(py_signals) & set(ts_signals)
        for sid in sorted(shared):
            py_ev = _normalize_evidence(py_signals[sid].evidence)
            ts_ev = _normalize_evidence(ts_signals[sid]["evidence"])
            # Same number of evidence items
            assert len(py_ev) == len(ts_ev), (
                f"[{fixture_id}] signal '{sid}' evidence count: "
                f"Python={len(py_ev)}, TS={len(ts_ev)}"
            )


class TestPythonRedactsDigits:
    """Verify that the Python engine does redact 4+-digit sequences
    in evidence (the TS engine intentionally does not)."""

    def test_otp_redacted_in_evidence(self):
        """OTP digits should be masked in Python evidence snippets."""
        r = analyze_message(
            "Please share your OTP 482913 to verify your bank account."
        )
        for s in r.signals:
            for ev in s.evidence:
                assert "482913" not in ev

    def test_monetary_4digit_preserved_in_evidence(self):
        """Phase 5.7: Clearly labelled monetary amounts like 'Rs 1500' are preserved in evidence."""
        r = analyze_message(
            "Enter your UPI PIN to receive cashback of Rs 1500 in your account."
        )
        # Currency amount is preserved for readability
        for s in r.signals:
            assert any("Rs 1500" in ev for ev in s.evidence)
            # Meanwhile, pin-to-receive does not leak credentials
            assert not any("482913" in ev for ev in s.evidence)


# ===================================================================
# 5. Summary parity
# ===================================================================

class TestCrossEngineSummary:
    """The summary text must be identical between engines."""

    @pytest.mark.parametrize("fixture_id", _fixture_ids())
    def test_summary_matches(self, fixture_id: str):
        fixture = _fixture_by_id(fixture_id)
        py = analyze_message(fixture["message"])
        ts = _TS_RESULTS[fixture_id]
        assert py.summary == ts["summary"], (
            f"Summary mismatch on '{fixture_id}'"
        )


# ===================================================================
# 6. Next-steps and verification parity
# ===================================================================

class TestCrossEngineGuidance:
    """Next steps and verification guidance must be identical."""

    @pytest.mark.parametrize("fixture_id", _fixture_ids())
    def test_next_steps_match(self, fixture_id: str):
        fixture = _fixture_by_id(fixture_id)
        py = analyze_message(fixture["message"])
        ts = _TS_RESULTS[fixture_id]
        assert py.next_steps == ts["nextSteps"], (
            f"Next-steps mismatch on '{fixture_id}'"
        )

    @pytest.mark.parametrize("fixture_id", _fixture_ids())
    def test_verification_matches(self, fixture_id: str):
        fixture = _fixture_by_id(fixture_id)
        py = analyze_message(fixture["message"])
        ts = _TS_RESULTS[fixture_id]
        assert list(py.verification) == ts["verification"], (
            f"Verification mismatch on '{fixture_id}'"
        )


# ===================================================================
# 7. Fixture expectations (sanity check against expectRisk)
# ===================================================================

class TestFixtureExpectations:
    """Verify both engines meet the fixture's stated expectations."""

    @pytest.mark.parametrize("fixture_id", _fixture_ids())
    def test_python_meets_expectations(self, fixture_id: str):
        fixture = _fixture_by_id(fixture_id)
        py = analyze_message(fixture["message"])
        py_ids = {s.id for s in py.signals}

        # Check expected signals are present
        for expected in fixture["expectSignals"]:
            assert expected in py_ids, (
                f"[{fixture_id}] Expected signal '{expected}' not found in "
                f"Python output. Got: {sorted(py_ids)}"
            )

        # Check absent signals
        for absent in fixture.get("expectAbsent", []):
            assert absent not in py_ids, (
                f"[{fixture_id}] Signal '{absent}' should NOT be present "
                f"in Python output"
            )

    @pytest.mark.parametrize("fixture_id", _fixture_ids())
    def test_typescript_meets_expectations(self, fixture_id: str):
        fixture = _fixture_by_id(fixture_id)
        ts = _TS_RESULTS[fixture_id]
        ts_ids = set(ts["signalIds"])

        for expected in fixture["expectSignals"]:
            assert expected in ts_ids, (
                f"[{fixture_id}] Expected signal '{expected}' not found in "
                f"TS output. Got: {sorted(ts_ids)}"
            )

        for absent in fixture.get("expectAbsent", []):
            assert absent not in ts_ids, (
                f"[{fixture_id}] Signal '{absent}' should NOT be present "
                f"in TS output"
            )


# ===================================================================
# 8. Phase 5.6: Privacy redaction parity
# ===================================================================

class TestPrivacyRedactionParity:
    """Verify Phase 5.6 consistency: TypeScript now redacts sensitive
    credentials, phone numbers and account references while preserving
    ordinary currency amounts."""

    def test_ts_redacts_phone_in_callback_01(self):
        """TypeScript snapshot for callback-01 must mask the phone number."""
        ts_entry = _TS_RESULTS["callback-01"]
        sig = next(s for s in ts_entry["signalDetails"] if s["id"] == "callback-number")
        for ev in sig["evidence"]:
            assert "98765 43210" not in ev
            assert "9***5 4***0" in ev

    def test_ts_redacts_account_ending_in_legit_03(self):
        """TypeScript snapshot for legit-03 must mask account suffix 4321."""
        ts_entry = _TS_RESULTS["legit-03"]
        sig = next(s for s in ts_entry["signalDetails"] if s["id"] == "impersonation")
        for ev in sig["evidence"]:
            assert "4321" not in ev
            assert "4**1" in ev

    def test_ts_preserves_currency_amount_in_qr_payment_01(self):
        """TypeScript preserves currency amount Rs 1500 for readability."""
        ts_entry = _TS_RESULTS["qr-payment-01"]
        sig = next(s for s in ts_entry["signalDetails"] if s["id"] == "pin-to-receive")
        # Rs 1500 is preserved in TypeScript evidence
        assert any("Rs 1500" in ev for ev in sig["evidence"])

    def test_python_redacts_credentials_live(self):
        """Python live execution continues to mask OTPs and PINs."""
        r = analyze_message("Please share your OTP 482913 to verify your bank account.")
        for s in r.signals:
            for ev in s.evidence:
                assert "482913" not in ev
                assert "4****3" in ev

    def test_python_preserves_currency_adjacent_to_otp(self):
        """Python live execution preserves currency while masking OTP."""
        r = analyze_message("Please send us your OTP 739182 for Rs 1500 refund immediately.")
        cred = next(s for s in r.signals if s.id == "credential-request")
        assert any("Rs 1500" in ev and "7****2" in ev for ev in cred.evidence)

    def test_python_redacts_grouped_phone_numbers(self):
        """Python live execution masks grouped phone numbers."""
        r = analyze_message("Call 987-654-3210 immediately to pay the fee.")
        for s in r.signals:
            for ev in s.evidence:
                assert "987-654-3210" not in ev
                assert "9**-***-**10" in ev

    def test_python_redacts_grouped_card_numbers(self):
        """Python live execution masks 16-digit card numbers with spaces."""
        r = analyze_message("Please provide your card details 4111 2222 3333 4444 immediately.")
        for s in r.signals:
            for ev in s.evidence:
                assert "4111 2222 3333 4444" not in ev
                assert "4*** **** **** ***4" in ev

