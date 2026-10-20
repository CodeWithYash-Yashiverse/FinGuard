"""Unit tests for the rule-based detection engine.

All test messages are synthetic — no real banking messages or credentials
are used.

Run from the ``backend/`` directory::

    python -m pytest tests/ -v
"""

from __future__ import annotations

import pytest

from app.detector import analyze_message, _redact_secrets
from app.schemas import RiskLevel, Severity, SignalCategory


# ===================================================================
# Helpers
# ===================================================================

def _signal_ids(result) -> set[str]:
    """Return the set of signal IDs from an analysis result."""
    return {s.id for s in result.signals}


def _has_signal(result, signal_id: str) -> bool:
    return signal_id in _signal_ids(result)


def _signal_categories(result) -> set[SignalCategory]:
    return {s.category for s in result.signals}


# ===================================================================
# 1. Suspicious messages — should detect warning signs
# ===================================================================

class TestSuspiciousMessages:
    """Messages with clear scam indicators."""

    def test_direct_otp_request(self):
        """A message directly asking to share an OTP should trigger
        credential-request with high severity."""
        msg = (
            "Dear customer, please share your OTP 482913 to verify "
            "your SBI account and avoid suspension."
        )
        result = analyze_message(msg)
        assert _has_signal(result, "credential-request")
        cred = next(s for s in result.signals if s.id == "credential-request")
        assert cred.severity == Severity.HIGH

    def test_upi_pin_request(self):
        """Asking the user to enter a UPI PIN to receive money is a
        high-severity payment scam indicator."""
        msg = (
            "Hi, I am calling from PhonePe customer care. Your cashback "
            "of Rs 2,500 is pending. Enter your UPI PIN on the collect "
            "request to receive the refund within 10 minutes."
        )
        result = analyze_message(msg)
        assert _has_signal(result, "pin-to-receive")
        assert result.risk_level == RiskLevel.HIGH_RISK

    def test_urgent_payment_demand_with_threat(self):
        """Urgency combined with a payment demand and account-blocking
        threat should yield high_risk."""
        msg = (
            "URGENT: Your HDFC account will be blocked immediately if you "
            "do not pay Rs 999 processing fee right now. Transfer the amount "
            "within 30 minutes or your card will be suspended."
        )
        result = analyze_message(msg)
        assert result.risk_level == RiskLevel.HIGH_RISK
        assert _has_signal(result, "urgency") or _has_signal(result, "account-threat")
        assert _has_signal(result, "payment-demand")

    def test_suspicious_link_with_impersonation(self):
        """A fake brand URL combined with KYC update language should be
        flagged as high_risk."""
        msg = (
            "Dear Customer, your SBI account will be BLOCKED today. "
            "Update your KYC immediately at http://sbi-kyc-update.xyz/verify "
            "and share the OTP sent to your mobile to confirm."
        )
        result = analyze_message(msg)
        assert result.risk_level == RiskLevel.HIGH_RISK
        # Should detect lookalike link AND credential request
        link_ids = {s.id for s in result.signals if s.category == SignalCategory.LINK}
        assert "link-lookalike" in link_ids or "link-tld" in link_ids
        assert _has_signal(result, "credential-request")

    def test_legal_threat_digital_arrest(self):
        """'Digital arrest' scam language is a high-severity urgency signal."""
        msg = (
            "This is CBI officer. A money laundering case has been "
            "registered against you. You are under digital arrest. "
            "Don't tell anyone or hang up."
        )
        result = analyze_message(msg)
        assert _has_signal(result, "legal-threat")
        assert _has_signal(result, "secrecy")
        assert result.risk_level == RiskLevel.HIGH_RISK

    def test_remote_access_app(self):
        """Asking to install AnyDesk or TeamViewer is a high-severity pattern."""
        msg = (
            "To fix your banking issue, please install AnyDesk from the "
            "Play Store and share the 9-digit code with our executive."
        )
        result = analyze_message(msg)
        assert _has_signal(result, "remote-access")
        assert result.risk_level == RiskLevel.HIGH_RISK

    def test_prize_scam(self):
        """'You have won' combined with a fee demand is suspicious or high."""
        msg = (
            "Congratulations! You have won a lucky draw prize of Rs 50,000. "
            "To claim your reward, pay the processing fee of Rs 500 "
            "at bit.ly/claim-prize"
        )
        result = analyze_message(msg)
        assert _has_signal(result, "too-good")
        assert _has_signal(result, "payment-demand")
        assert result.risk_level in (RiskLevel.HIGH_RISK, RiskLevel.SUSPICIOUS)

    def test_callback_number(self):
        """A message asking to call an unverified number should trigger
        callback-number."""
        msg = (
            "Your parcel is held at customs. Call +91 98765 43210 "
            "immediately to pay the release fee and avoid legal action."
        )
        result = analyze_message(msg)
        assert _has_signal(result, "callback-number")

    def test_multiple_signals_high_risk(self):
        """A message with many medium-severity signals should be high_risk
        when the count threshold (≥3 medium) is met."""
        msg = (
            "Your ICICI account KYC is pending. Update immediately or your "
            "account will be blocked. Pay Rs 200 verification fee. "
            "Claim your reward points before they expire today."
        )
        result = analyze_message(msg)
        assert result.risk_level == RiskLevel.HIGH_RISK
        assert len(result.signals) >= 3


# ===================================================================
# 2. Legitimate messages — should NOT produce strong warning signs
# ===================================================================

class TestLegitimateMessages:
    """Normal banking and payment messages that should not be flagged."""

    def test_payment_confirmation(self):
        """A normal transaction confirmation should have no strong signs."""
        msg = (
            "Your payment of Rs 499.00 to Amazon has been successful. "
            "Transaction ID: TXN20261019ABC. Available balance: Rs 12,340."
        )
        result = analyze_message(msg)
        assert result.risk_level == RiskLevel.NO_STRONG_SIGNS
        # No high-severity signals
        assert not any(s.severity == Severity.HIGH for s in result.signals)

    def test_bank_statement_notification(self):
        """A routine bank statement notification mentioning a brand name
        plus 'account' triggers the impersonation rule (requires
        co-occurrence).  This is consistent with the TS engine.
        It should be at most suspicious, never high_risk."""
        msg = (
            "Your HDFC Bank account statement for October 2026 is ready. "
            "View it in the official HDFC Mobile Banking app."
        )
        result = analyze_message(msg)
        assert result.risk_level != RiskLevel.HIGH_RISK

    def test_otp_safety_warning(self):
        """An informational message that says 'Never share your OTP' must
        NOT trigger credential-request — the skip-if-preceded-by guard
        should catch the negation."""
        msg = (
            "OTP for your transaction of INR 499.00 at Amazon is 482913. "
            "Valid for 10 minutes. Do not share this OTP with anyone. "
            "- HDFC Bank"
        )
        result = analyze_message(msg)
        assert not _has_signal(result, "credential-request")

    def test_never_share_advisory(self):
        """An advisory message about never sharing PINs should not flag
        credential-request."""
        msg = (
            "Beware of messages asking for OTPs. Never share your UPI PIN "
            "or OTP with anyone. Your bank will never ask for it."
        )
        result = analyze_message(msg)
        assert not _has_signal(result, "credential-request")

    def test_bill_reminder(self):
        """A normal bill reminder with a due date is not a scam."""
        msg = (
            "Your electricity bill of Rs 1,200 is due on 25 October 2026. "
            "Pay through the official MSEB portal or your banking app."
        )
        result = analyze_message(msg)
        assert result.risk_level == RiskLevel.NO_STRONG_SIGNS

    def test_delivery_notification(self):
        """A simple delivery update should not trigger high-risk signals."""
        msg = (
            "Your Amazon order #408-1234567-8901234 has been shipped "
            "and will be delivered by 21 October 2026."
        )
        result = analyze_message(msg)
        assert result.risk_level == RiskLevel.NO_STRONG_SIGNS


# ===================================================================
# 3. Ambiguous messages — classification depends on context
# ===================================================================

class TestAmbiguousMessages:
    """Messages that have some suspicious characteristics but are not
    clearly scams."""

    def test_unfamiliar_link_without_context(self):
        """A link with an unusual TLD but no other signals is suspicious
        (link produces a low or medium signal)."""
        msg = "Check out this link: https://example.xyz/payment-info"
        result = analyze_message(msg)
        # Should detect the unusual TLD but not be high_risk
        assert result.risk_level in (RiskLevel.SUSPICIOUS, RiskLevel.NO_STRONG_SIGNS)
        assert SignalCategory.LINK in _signal_categories(result)

    def test_refund_without_payment_request(self):
        """Mentioning a refund without asking for payment or credentials
        should not be high_risk."""
        msg = (
            "Your refund of Rs 500 has been processed and will be credited "
            "to your account within 3 business days."
        )
        result = analyze_message(msg)
        assert result.risk_level != RiskLevel.HIGH_RISK

    def test_urgent_reminder_without_scam(self):
        """An urgent reminder about a real due date should not automatically
        be high_risk without other scam signals."""
        msg = (
            "Reminder: Your credit card payment of Rs 15,000 is due today. "
            "Please pay through your banking app to avoid late charges."
        )
        result = analyze_message(msg)
        # May trigger urgency, but not high_risk unless combined with other strong signals
        assert result.risk_level != RiskLevel.HIGH_RISK

    def test_shortened_link_only(self):
        """A shortened link without other scam context is suspicious but
        not necessarily high_risk."""
        msg = "Please review this document: https://bit.ly/3xY4zW9"
        result = analyze_message(msg)
        assert _has_signal(result, "link-shortener")
        # One medium signal → suspicious
        assert result.risk_level == RiskLevel.SUSPICIOUS

    def test_ip_address_link(self):
        """A link pointing to a raw IP is high-severity for the link check."""
        msg = "Login here: http://192.168.1.100/banking-portal"
        result = analyze_message(msg)
        assert _has_signal(result, "link-ip")
        # High severity link → high_risk
        assert result.risk_level == RiskLevel.HIGH_RISK


# ===================================================================
# 4. Input edge cases — empty, whitespace, unusual content
# ===================================================================

class TestInputEdgeCases:
    """Verify the detector handles edge cases without crashing."""

    def test_empty_string(self):
        """Empty input should return a valid result with no signals."""
        result = analyze_message("")
        assert result.risk_level == RiskLevel.NO_STRONG_SIGNS
        assert result.signals == []
        assert len(result.summary) > 0
        assert len(result.next_steps) > 0

    def test_whitespace_only(self):
        """Whitespace-only input should return no_strong_signs."""
        result = analyze_message("   \t\n  ")
        assert result.risk_level == RiskLevel.NO_STRONG_SIGNS
        assert result.signals == []

    def test_very_short_input(self):
        """Very short input should still return a valid result."""
        result = analyze_message("Hi")
        assert result.risk_level == RiskLevel.NO_STRONG_SIGNS

    def test_long_benign_input(self):
        """A long but benign message should not crash or be flagged."""
        msg = "This is a normal message. " * 200
        result = analyze_message(msg)
        assert result.risk_level == RiskLevel.NO_STRONG_SIGNS

    def test_unicode_normalization(self):
        """Non-ASCII text should be handled via NFKC normalization."""
        # ＯＴＰ (fullwidth) should normalize to OTP
        msg = "Please share your ＯＴＰ immediately to avoid account block."
        result = analyze_message(msg)
        # After NFKC normalization, "ＯＴＰ" → "OTP"
        assert _has_signal(result, "credential-request")

    def test_numeric_only(self):
        """A message containing only numbers should not crash."""
        result = analyze_message("12345678901234567890")
        assert result.risk_level == RiskLevel.NO_STRONG_SIGNS

    def test_special_characters(self):
        """Special chars and emoji should not crash the detector."""
        result = analyze_message("🔒 ⚠️ !@#$%^&*() 💰 🏦")
        assert result.risk_level == RiskLevel.NO_STRONG_SIGNS


# ===================================================================
# 5. Response structure validation
# ===================================================================

class TestResponseStructure:
    """Verify the response matches the expected schema contract."""

    def test_result_has_all_required_fields(self):
        result = analyze_message("Test message for structure check.")
        assert result.risk_level in RiskLevel
        assert isinstance(result.summary, str) and len(result.summary) > 0
        assert isinstance(result.signals, list)
        assert isinstance(result.next_steps, list) and len(result.next_steps) > 0
        assert isinstance(result.verification, list) and len(result.verification) > 0
        assert result.engine.name == "FinGuard heuristic engine"
        assert result.engine.version == "1.0.0"
        assert result.engine.mode == "local"
        assert isinstance(result.analyzed_at, str) and len(result.analyzed_at) > 0

    def test_risk_level_values_are_valid(self):
        """Only the three allowed risk levels should ever appear."""
        for msg in [
            "",
            "Normal payment of Rs 100 confirmed.",
            "Share your OTP now to avoid account block at http://fake-sbi.xyz",
        ]:
            result = analyze_message(msg)
            assert result.risk_level in (
                RiskLevel.HIGH_RISK,
                RiskLevel.SUSPICIOUS,
                RiskLevel.NO_STRONG_SIGNS,
            )

    def test_signal_fields(self):
        """Each signal should have all required fields."""
        result = analyze_message(
            "Share your OTP 482913 to verify your SBI account."
        )
        for signal in result.signals:
            assert isinstance(signal.id, str) and len(signal.id) > 0
            assert signal.category in SignalCategory
            assert isinstance(signal.title, str) and len(signal.title) > 0
            assert signal.severity in Severity
            assert isinstance(signal.explanation, str) and len(signal.explanation) > 0
            assert isinstance(signal.evidence, list)

    def test_camel_case_serialization(self):
        """JSON output must use camelCase field names for frontend compat."""
        result = analyze_message("Share your OTP now to verify your account.")
        data = result.model_dump(by_alias=True)
        assert "riskLevel" in data
        assert "nextSteps" in data
        assert "analyzedAt" in data
        # snake_case keys should NOT appear in aliased output
        assert "risk_level" not in data
        assert "next_steps" not in data
        assert "analyzed_at" not in data

    def test_empty_signals_is_valid_list(self):
        """When no signals are found, signals should be an empty list."""
        result = analyze_message("Hello, how are you doing today?")
        assert result.signals == []
        assert result.risk_level == RiskLevel.NO_STRONG_SIGNS


# ===================================================================
# 6. Privacy and secret redaction
# ===================================================================

class TestPrivacyAndRedaction:
    """Verify sensitive data is not exposed in evidence."""

    def test_otp_digits_redacted_in_evidence(self):
        """OTP digit sequences (4+) must be partially masked in evidence."""
        msg = "Please share your OTP 482913 to complete the transaction."
        result = analyze_message(msg)
        # The evidence snippets should NOT contain the full OTP
        for signal in result.signals:
            for evidence in signal.evidence:
                assert "482913" not in evidence, (
                    f"Full OTP '482913' found in evidence: {evidence}"
                )

    def test_card_number_redacted_in_evidence(self):
        """Long digit sequences (card numbers) must be partially masked."""
        msg = "Please confirm your card number 4111111111111111 to process."
        result = analyze_message(msg)
        for signal in result.signals:
            for evidence in signal.evidence:
                assert "4111111111111111" not in evidence

    def test_redact_secrets_function_directly(self):
        """Direct test of the _redact_secrets helper."""
        assert _redact_secrets("OTP is 482913") == "OTP is 4****3"
        assert _redact_secrets("PIN 1234") == "PIN 1**4"
        assert _redact_secrets("Rs 500") == "Rs 500"  # 3 digits: no change
        assert _redact_secrets("Card 4111222233334444") == "Card 4**************4"
        assert _redact_secrets("no digits here") == "no digits here"

    def test_urls_not_fetched(self):
        """The detector should only parse URLs as text, never fetch them.

        We verify this indirectly: the function is pure and has no
        network-related imports or side effects.  The function signature
        takes a string and returns an AnalysisResult — no HTTP client
        is involved.
        """
        msg = "Visit http://malicious-site.xyz/steal-data right now!"
        # This should complete instantly (no network wait)
        result = analyze_message(msg)
        assert result is not None
        # Link signals should be present from text parsing
        assert SignalCategory.LINK in _signal_categories(result)

    def test_no_message_persistence(self):
        """Repeated calls should not build up any state."""
        msg = "Share your OTP 999999 immediately."
        r1 = analyze_message(msg)
        r2 = analyze_message(msg)
        # Results should be structurally equivalent (same signals)
        assert _signal_ids(r1) == _signal_ids(r2)
        # But they are independent objects
        assert r1 is not r2


# ===================================================================
# 7. Classification thresholds
# ===================================================================

class TestClassificationThresholds:
    """Verify the risk-level classification logic matches the TypeScript
    engine thresholds:
      - high >= 1 OR medium >= 3 → high_risk
      - medium >= 1 OR low >= 2   → suspicious
      - else                      → no_strong_signs
    """

    def test_single_high_severity_is_high_risk(self):
        """One high-severity signal → high_risk."""
        msg = "Install AnyDesk now to fix your banking issue."
        result = analyze_message(msg)
        assert any(s.severity == Severity.HIGH for s in result.signals)
        assert result.risk_level == RiskLevel.HIGH_RISK

    def test_single_medium_is_suspicious(self):
        """One medium-severity signal without high → suspicious."""
        msg = (
            "URGENT: Please respond to this message immediately to keep "
            "your service active."
        )
        result = analyze_message(msg)
        # Should trigger urgency (medium) but nothing high
        assert any(s.severity == Severity.MEDIUM for s in result.signals)
        assert not any(s.severity == Severity.HIGH for s in result.signals)
        assert result.risk_level == RiskLevel.SUSPICIOUS

    def test_no_signals_is_no_strong_signs(self):
        """No signals at all → no_strong_signs."""
        msg = "Good morning! Have a wonderful day."
        result = analyze_message(msg)
        assert result.signals == []
        assert result.risk_level == RiskLevel.NO_STRONG_SIGNS

    def test_single_low_is_no_strong_signs(self):
        """One low-severity signal → no_strong_signs."""
        msg = "More info at https://example.com/info"
        result = analyze_message(msg)
        # The link is benign → link-present (low severity)
        if result.signals and all(s.severity == Severity.LOW for s in result.signals):
            assert result.risk_level == RiskLevel.NO_STRONG_SIGNS


# ===================================================================
# 8. False-positive reduction
# ===================================================================

class TestFalsePositiveReduction:
    """Messages that contain scam-like keywords but in safe context."""

    def test_do_not_share_otp_not_flagged(self):
        """'Do not share this OTP' should NOT trigger credential-request."""
        msg = "Your OTP is 847291. Do not share this OTP with anyone."
        result = analyze_message(msg)
        assert not _has_signal(result, "credential-request")

    def test_never_share_pin_not_flagged(self):
        """'Never share your UPI PIN' is informational, not a credential request."""
        msg = (
            "Security reminder: Never share your UPI PIN or OTP with "
            "anyone, including bank staff."
        )
        result = analyze_message(msg)
        assert not _has_signal(result, "credential-request")

    def test_impersonation_requires_action_word(self):
        """Mentioning a brand name alone (without account/kyc/etc.) should
        NOT trigger impersonation."""
        msg = "I use SBI for my savings and HDFC for my credit card."
        result = analyze_message(msg)
        assert not _has_signal(result, "impersonation")

    def test_brand_with_action_triggers_impersonation(self):
        """Brand name + action keyword (account, kyc, etc.) should trigger."""
        msg = (
            "Dear SBI customer, your account verification is pending. "
            "Click the link to update your details."
        )
        result = analyze_message(msg)
        assert _has_signal(result, "impersonation")

    def test_successful_payment_not_flagged_as_demand(self):
        """'Payment of Rs 500 was successful' should not be a payment demand."""
        msg = "Your payment of Rs 500 was successful. Thank you for shopping."
        result = analyze_message(msg)
        assert not _has_signal(result, "payment-demand")


# ===================================================================
# 9. Link analysis details
# ===================================================================

class TestLinkAnalysis:
    """Detailed tests for link detection heuristics."""

    def test_official_domain_not_flagged_as_lookalike(self):
        """Real SBI domain should not trigger lookalike detection."""
        msg = "Login at https://onlinesbi.sbi to check your balance."
        result = analyze_message(msg)
        assert not _has_signal(result, "link-lookalike")

    def test_fake_brand_domain_flagged(self):
        """A domain containing 'sbi' but not official should be flagged."""
        msg = "Update KYC at http://sbi-secure-login.xyz/verify"
        result = analyze_message(msg)
        link_ids = _signal_ids(result)
        assert "link-lookalike" in link_ids or "link-tld" in link_ids

    def test_ip_address_link_detected(self):
        """A raw IP link should trigger link-ip."""
        msg = "Verify your account at http://45.67.89.123/login"
        result = analyze_message(msg)
        assert _has_signal(result, "link-ip")

    def test_punycode_domain_detected(self):
        """A punycode domain should trigger link-punycode."""
        msg = "Login at http://xn--sbi-bank.xyz/secure"
        result = analyze_message(msg)
        assert _has_signal(result, "link-punycode")

    def test_url_shortener_detected(self):
        """Known shortener domains should be detected."""
        msg = "Click this link: https://bit.ly/3abc123"
        result = analyze_message(msg)
        assert _has_signal(result, "link-shortener")

    def test_insecure_http_detected(self):
        """Plain http:// links should trigger link-insecure."""
        msg = "Login at http://example.com/banking to check balance."
        result = analyze_message(msg)
        assert _has_signal(result, "link-insecure")

    def test_benign_https_link_gets_link_present(self):
        """An https link with a common TLD and no issues gets link-present."""
        msg = "Read our blog at https://example.com/blog/safety-tips"
        result = analyze_message(msg)
        assert _has_signal(result, "link-present")
        lp = next(s for s in result.signals if s.id == "link-present")
        assert lp.severity == Severity.LOW
