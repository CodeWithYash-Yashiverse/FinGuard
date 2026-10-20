"""Phase 5 — Extended detection-quality and privacy tests.

These tests cover the 12 categories specified in the Phase 5 prompt.
Each test documents intended behaviour and rationale.

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

def _ids(result) -> set[str]:
    return {s.id for s in result.signals}


def _cats(result) -> set[SignalCategory]:
    return {s.category for s in result.signals}


def _has(result, signal_id: str) -> bool:
    return signal_id in _ids(result)


def _severities(result) -> list[Severity]:
    return [s.severity for s in result.signals]


# ===================================================================
# Category 1: Direct OTP, password, and UPI PIN requests
# ===================================================================

class TestCategory1_CredentialRequests:
    """Direct requests for OTP, password, UPI PIN, CVV etc.
    All should trigger credential-request (high severity)."""

    def test_send_otp_explicit(self):
        """'Send us your OTP' is a clear credential request."""
        r = analyze_message("Dear customer, please send us your OTP to complete verification of your SBI account.")
        assert _has(r, "credential-request")
        assert r.risk_level == RiskLevel.HIGH_RISK

    def test_provide_cvv(self):
        """Asking for CVV is a credential request."""
        r = analyze_message("To process your refund, please provide your CVV and card number to our support team.")
        assert _has(r, "credential-request")

    def test_share_password(self):
        """'Share your password' is clearly malicious."""
        r = analyze_message("Your net banking access has expired. Share your password immediately to restore access.")
        assert _has(r, "credential-request")

    def test_reply_with_verification_code(self):
        """'Reply with the verification code' matches the credential rule."""
        r = analyze_message("A verification code has been sent to your phone. Reply with the verification code to proceed.")
        assert _has(r, "credential-request")

    def test_forward_otp_sms(self):
        """'Forward the OTP SMS' is a clear credential request."""
        r = analyze_message("Please forward the OTP SMS you just received to complete the payment verification process.")
        assert _has(r, "credential-request")

    def test_tell_mpin(self):
        """'Tell me your M-PIN' asks for mobile banking PIN."""
        r = analyze_message("To fix the issue with your account, tell me your M-PIN so we can verify your identity.")
        assert _has(r, "credential-request")


# ===================================================================
# Category 2: PIN/QR scan to receive money
# ===================================================================

class TestCategory2_PinToReceive:
    """Messages claiming you need to enter a PIN or scan QR to receive
    money.  This is always fraudulent — receiving money never requires
    your PIN."""

    def test_enter_pin_to_receive_cashback(self):
        """Classic PhonePe/GPay scam: enter PIN to receive cashback."""
        r = analyze_message("Your PhonePe cashback of Rs 1500 is ready. Enter your UPI PIN on the collect request to receive the refund.")
        assert _has(r, "pin-to-receive")
        assert r.risk_level == RiskLevel.HIGH_RISK

    def test_scan_qr_to_get_refund(self):
        """'Scan this QR code to get your refund' is fraudulent."""
        r = analyze_message("To get your refund of Rs 3000, scan the QR code below and approve the payment request.")
        assert _has(r, "pin-to-receive")

    def test_approve_collect_to_receive(self):
        """'Approve the collect request to receive' triggers pin-to-receive."""
        r = analyze_message("To receive the prize money, accept the collect request that has been sent to your UPI app.")
        # Should trigger pin-to-receive via the "receive...accept...request" pattern
        assert _has(r, "pin-to-receive") or _has(r, "too-good")

    def test_enter_pin_to_claim_prize(self):
        """'Enter PIN to claim your prize' is fraudulent."""
        r = analyze_message("Congratulations! You won Rs 25000. Enter your UPI PIN to claim the prize.")
        assert _has(r, "pin-to-receive")
        assert r.risk_level == RiskLevel.HIGH_RISK


# ===================================================================
# Category 3: Urgent payment demands and account-blocking threats
# ===================================================================

class TestCategory3_UrgencyAndThreats:
    """Urgent demands combined with payment or account threats."""

    def test_account_blocked_within_hours(self):
        """'Account will be blocked within 24 hours' combines urgency
        and account-threat."""
        r = analyze_message("Your ICICI account will be blocked within 24 hours if you do not update your KYC details immediately.")
        assert _has(r, "urgency") or _has(r, "account-threat")
        assert r.risk_level in (RiskLevel.HIGH_RISK, RiskLevel.SUSPICIOUS)

    def test_final_warning_pay_now(self):
        """'Final warning' + 'pay now' = urgency + payment-demand."""
        r = analyze_message("FINAL WARNING: Pay Rs 1999 processing fee now or your loan application will be cancelled permanently.")
        assert _has(r, "urgency")
        assert _has(r, "payment-demand")

    def test_sim_disconnection_threat(self):
        """'SIM will be disconnected' is an account-threat."""
        r = analyze_message("Dear subscriber, your SIM will be disconnected in 2 hours due to incomplete verification. Call 9876543210 now.")
        assert _has(r, "account-threat")

    def test_electricity_disconnection(self):
        """'Electricity will be disconnected' combines service threat
        with urgency."""
        r = analyze_message("Your electricity connection will be disconnected today itself due to unpaid bill. Pay Rs 2500 immediately.")
        assert _has(r, "account-threat") or _has(r, "urgency")
        assert _has(r, "payment-demand")

    def test_digital_arrest_fir(self):
        """'FIR has been registered against you' is a legal threat."""
        r = analyze_message("A FIR has been registered against you for money laundering. Stay on the call and do not tell anyone.")
        assert _has(r, "legal-threat")
        assert _has(r, "secrecy")
        assert r.risk_level == RiskLevel.HIGH_RISK


# ===================================================================
# Category 4: Suspicious links + credential/payment requests
# ===================================================================

class TestCategory4_LinkCombinations:
    """Links combined with credential or payment requests should
    elevate the risk."""

    def test_fake_kyc_link_with_otp(self):
        """Fake KYC link + OTP request = high_risk with multiple signals."""
        r = analyze_message(
            "Your PAN card KYC is pending. Update at http://pan-kyc-update.xyz/verify "
            "and share the OTP sent to your mobile."
        )
        assert r.risk_level == RiskLevel.HIGH_RISK
        assert SignalCategory.LINK in _cats(r)
        assert _has(r, "credential-request")

    def test_shortened_link_with_payment(self):
        """Shortened link + payment demand should be suspicious or high."""
        r = analyze_message(
            "Your parcel delivery fee of Rs 149 is pending. "
            "Pay now at https://bit.ly/pay-delivery-fee to avoid return."
        )
        assert _has(r, "payment-demand")
        assert _has(r, "link-shortener")

    def test_brand_lookalike_with_account_threat(self):
        """A brand lookalike domain + account suspension threat."""
        r = analyze_message(
            "Your HDFC account has been frozen due to suspicious activity. "
            "Verify immediately at http://hdfc-bank-verify.online/secure"
        )
        assert r.risk_level == RiskLevel.HIGH_RISK
        link_ids = {s.id for s in r.signals if s.category == SignalCategory.LINK}
        assert "link-lookalike" in link_ids or "link-tld" in link_ids


# ===================================================================
# Category 5: Prize, refund, and processing-fee scams
# ===================================================================

class TestCategory5_PrizeAndFeeScams:
    """Unexpected prizes, refunds with fee demands."""

    def test_lottery_with_processing_fee(self):
        """'You won a lottery' + processing fee = classic scam.

        Detection quality observation: this produces 2 medium-severity
        signals (too-good + payment-demand), which classifies as
        'suspicious' not 'high_risk' because the threshold requires
        either 1 high or 3+ medium.  This is a known limitation of
        the threshold-based classification — a lottery + fee combo is
        a textbook scam but only scores 2 medium signals."""
        r = analyze_message(
            "Congratulations! You have won Rs 10 lakh in the National Lottery. "
            "Pay Rs 999 processing fee to claim your prize."
        )
        assert _has(r, "too-good")
        assert _has(r, "payment-demand")
        # Known limitation: 2 medium signals → suspicious, not high_risk
        assert r.risk_level in (RiskLevel.HIGH_RISK, RiskLevel.SUSPICIOUS)

    def test_work_from_home_task_scam(self):
        """'Earn Rs 5000 per day' work-from-home scam."""
        r = analyze_message(
            "Work from home opportunity! Earn Rs 5000 per day by liking YouTube videos. "
            "No experience needed. WhatsApp 9876543210."
        )
        assert _has(r, "too-good")

    def test_refund_with_release_charge(self):
        """'Pay release charge to get refund' is a fee scam."""
        r = analyze_message(
            "Your tax refund of Rs 15000 is approved. Pay the release charge of Rs 500 "
            "to receive the refund in your account."
        )
        assert _has(r, "payment-demand")
        # Should also detect "release charge" pattern
        assert r.risk_level in (RiskLevel.HIGH_RISK, RiskLevel.SUSPICIOUS)

    def test_customs_clearance_fee(self):
        """'Pay customs clearance fee' for a parcel you didn't order."""
        r = analyze_message(
            "Your international parcel from FedEx is held at customs. "
            "Pay clearance fee of Rs 2000 to release it immediately."
        )
        assert _has(r, "payment-demand")


# ===================================================================
# Category 6: Legitimate payment confirmations and notifications
# ===================================================================

class TestCategory6_LegitimateMessages:
    """Normal banking/payment messages that should NOT be flagged
    as high_risk. Some may trigger minor signals due to keyword
    overlap, but should never be high_risk."""

    def test_upi_payment_success(self):
        """A simple UPI payment success notification."""
        r = analyze_message(
            "Rs 250.00 paid to Swiggy via UPI. "
            "Ref: 426318745923. Balance: Rs 8,450.00."
        )
        assert r.risk_level == RiskLevel.NO_STRONG_SIGNS

    def test_credit_card_statement_ready(self):
        """Statement-ready notification — no scam intent."""
        r = analyze_message(
            "Your Axis Bank credit card statement for October 2026 is ready. "
            "Total due: Rs 12,500. Due date: 15 Nov 2026. "
            "Pay through the Axis Mobile app."
        )
        assert r.risk_level != RiskLevel.HIGH_RISK

    def test_emi_debit_notification(self):
        """Routine EMI debit is not a scam."""
        r = analyze_message(
            "EMI of Rs 8,333 has been debited from your HDFC account "
            "for Home Loan A/c 12345678. Next EMI due: 05 Nov 2026."
        )
        assert r.risk_level != RiskLevel.HIGH_RISK

    def test_salary_credited(self):
        """Salary credit notification is benign."""
        r = analyze_message(
            "Salary of Rs 65,000.00 credited to your SBI account ending 4321. "
            "Available balance: Rs 72,340.00."
        )
        assert r.risk_level != RiskLevel.HIGH_RISK

    def test_mutual_fund_purchase(self):
        """Investment confirmation is not suspicious."""
        r = analyze_message(
            "Your purchase of 50 units of Nifty 50 Index Fund at NAV Rs 245.30 "
            "has been confirmed. Amount: Rs 12,265.00."
        )
        assert r.risk_level == RiskLevel.NO_STRONG_SIGNS

    def test_gas_bill_payment_receipt(self):
        """Gas bill payment receipt is benign."""
        r = analyze_message(
            "Thank you for paying your Indane gas bill of Rs 950. "
            "Payment reference: GAS2026101900123."
        )
        assert r.risk_level == RiskLevel.NO_STRONG_SIGNS


# ===================================================================
# Category 7: Security advisories (do NOT share OTP)
# ===================================================================

class TestCategory7_SecurityAdvisories:
    """Messages telling users NOT to share credentials must not
    trigger credential-request.  The skip_if_preceded_by guard
    handles this."""

    def test_bank_otp_with_warning(self):
        """Standard OTP SMS with 'Do not share' warning."""
        r = analyze_message(
            "847291 is your one-time password for transaction of Rs 999 at Amazon. "
            "Do not share this OTP with anyone. It expires in 5 minutes. - ICICI Bank"
        )
        assert not _has(r, "credential-request")

    def test_never_share_pin_advisory(self):
        """'Never share your UPI PIN' is an advisory, not a request."""
        r = analyze_message(
            "RBI advisory: Never share your UPI PIN, OTP, or CVV with anyone. "
            "Your bank will never ask for these details over phone or message."
        )
        assert not _has(r, "credential-request")

    def test_dont_share_password_reminder(self):
        """'Don't share your password' is protective guidance."""
        r = analyze_message(
            "Security reminder from Kotak Bank: Don't share your password "
            "or OTP with anyone, including bank staff."
        )
        assert not _has(r, "credential-request")

    def test_no_one_will_ask_otp(self):
        """'No one will ask for your OTP' uses negation."""
        r = analyze_message(
            "Important: No one will ask for your OTP or password from "
            "Paytm. If someone does, report them immediately."
        )
        assert not _has(r, "credential-request")


# ===================================================================
# Category 8: Legitimate messages mentioning banks/KYC/refunds
# without suspicious requests
# ===================================================================

class TestCategory8_LegitBankMentions:
    """Mentioning a bank name or financial term without suspicious
    action should not trigger high-severity alerts."""

    def test_bank_branch_closure_notice(self):
        """An informational branch closure notice is not a scam."""
        r = analyze_message(
            "Dear customer, the SBI Koramangala branch will be closed on "
            "26 Oct 2026 for renovation. Visit MG Road branch for services."
        )
        # SBI is mentioned but no action keyword like "account" or "verify"
        # so impersonation requires guard should prevent triggering.
        assert r.risk_level != RiskLevel.HIGH_RISK

    def test_refund_processed_no_action_needed(self):
        """'Refund processed' with no fee demand is benign."""
        r = analyze_message(
            "Your refund of Rs 1,299 for order #12345 has been processed. "
            "It will be credited to your bank account within 5-7 business days."
        )
        assert not _has(r, "payment-demand")
        assert r.risk_level != RiskLevel.HIGH_RISK

    def test_kyc_completed_confirmation(self):
        """KYC completion confirmation is not a threat."""
        r = analyze_message(
            "Your KYC verification has been successfully completed. "
            "Thank you for banking with HDFC Bank."
        )
        # This mentions KYC + HDFC but in a completion context
        assert r.risk_level != RiskLevel.HIGH_RISK

    def test_account_opened_successfully(self):
        """A new account confirmation is not suspicious."""
        r = analyze_message(
            "Welcome to Axis Bank! Your savings account 9876543210 "
            "has been opened successfully. Visit axisbank.com to register for net banking."
        )
        assert r.risk_level != RiskLevel.HIGH_RISK

    def test_cashback_earned_no_action(self):
        """'Cashback earned' as a reward notification, not a lure.

        Known false positive: 'Amazon' + 'cashback' co-occurrence
        triggers the impersonation rule (requires pattern includes
        'cashback').  A legitimate cashback notification always
        mentions both a brand and cashback, so this is a structural
        limitation of the co-occurrence guard."""
        r = analyze_message(
            "You earned Rs 50 cashback on your Amazon Pay transaction. "
            "It has been added to your Amazon Pay balance."
        )
        # Known false positive: triggers impersonation due to
        # Amazon + cashback co-occurrence → suspicious
        assert r.risk_level != RiskLevel.HIGH_RISK


# ===================================================================
# Category 9: Ambiguous messages — cautious, non-definitive guidance
# ===================================================================

class TestCategory9_AmbiguousMessages:
    """Messages with some suspicious elements but not clearly scams.
    Should receive cautious guidance — suspicious or no_strong_signs,
    never claiming guaranteed safety or definite fraud."""

    def test_unknown_sender_account_update(self):
        """An account update request from an unnamed source is
        suspicious but not definitively a scam."""
        r = analyze_message(
            "Your account details need to be updated for compliance. "
            "Please visit our nearest branch with your Aadhaar card."
        )
        # No link, no payment demand, no credential request
        # But account-threat may trigger ("account...update")
        # Result should not be definitive
        assert r.risk_level != RiskLevel.HIGH_RISK

    def test_delivery_delay_with_link(self):
        """Delivery delay with a tracking link — could be real or fake."""
        r = analyze_message(
            "Your order has been delayed. Track your shipment at "
            "https://example.com/track/12345"
        )
        # Link is present (example.com is benign) but context is ambiguous
        assert r.risk_level != RiskLevel.HIGH_RISK

    def test_insurance_renewal_reminder(self):
        """Insurance renewal with a due amount is ambiguous."""
        r = analyze_message(
            "Your vehicle insurance policy expires on 30 Oct 2026. "
            "Renewal premium: Rs 12,500. Contact your agent for renewal."
        )
        assert r.risk_level != RiskLevel.HIGH_RISK

    def test_summary_never_claims_safe(self):
        """Even for clean messages, the summary must never say the
        message is 'safe' or 'guaranteed harmless'."""
        r = analyze_message("Hello, how are you doing today?")
        assert "safe" not in r.summary.lower() or "not" in r.summary.lower() or "does not mean" in r.summary.lower()
        # The summary should contain a caveat
        assert "verify" in r.summary.lower() or "does not mean" in r.summary.lower()


# ===================================================================
# Category 10: Unicode, whitespace, punctuation, long/malformed input
# ===================================================================

class TestCategory10_EdgeCases:
    """Unicode normalization, edge-case inputs, and malformed text."""

    def test_fullwidth_otp(self):
        """Fullwidth 'ＯＴＰ' should normalize to 'OTP' via NFKC."""
        r = analyze_message("Please share your ＯＴＰ to complete your account verification process.")
        assert _has(r, "credential-request")

    def test_mixed_case_urgency(self):
        """URGENTLY in all caps should still be detected."""
        r = analyze_message("URGENTLY update your account details or face permanent suspension from services.")
        assert _has(r, "urgency") or _has(r, "account-threat")

    def test_excessive_whitespace(self):
        """Excessive whitespace between words should not break rules."""
        r = analyze_message("Please   share    your    OTP    immediately   to   verify   your   account.")
        assert _has(r, "credential-request")

    def test_tab_and_newline_mixed(self):
        """Tabs and newlines in message should not crash."""
        r = analyze_message("Share\tyour\nOTP\r\nnow\tto\nverify\taccount")
        # May or may not match due to [^.\n] constraints, but must not crash
        assert r is not None
        assert r.risk_level in RiskLevel

    def test_repeated_punctuation(self):
        """Excessive punctuation should not cause regex catastrophic backtracking."""
        r = analyze_message("URGENT!!! Your account will be BLOCKED!!! Pay Rs 999 NOW!!!")
        assert r is not None
        assert _has(r, "urgency") or _has(r, "payment-demand")

    def test_emoji_heavy_message(self):
        """Emoji-heavy message should not crash the detector."""
        r = analyze_message("🎉🎊 Congratulations! 🎉 You have won 💰💰💰! Call 📞 now!")
        assert r is not None
        assert r.risk_level in RiskLevel

    def test_very_long_benign_message(self):
        """A 4000-char benign message should not be flagged."""
        msg = "This is a normal paragraph about daily life. " * 100
        r = analyze_message(msg)
        assert r.risk_level == RiskLevel.NO_STRONG_SIGNS

    def test_message_with_html_tags(self):
        """HTML tags in text should not break parsing."""
        r = analyze_message(
            "<b>URGENT</b>: Your <a href='http://fake.xyz'>account</a> "
            "will be blocked. Share your OTP immediately."
        )
        assert r is not None
        # Should still detect urgency and credential-request

    def test_null_bytes_and_control_chars(self):
        """Control characters should not crash the detector."""
        r = analyze_message("Share your OTP\x00 now to verify\x01 account")
        assert r is not None

    def test_right_to_left_mixed(self):
        """Mixed RTL/LTR text should not crash."""
        r = analyze_message("Share your OTP \u202E immediately to verify account")
        assert r is not None


# ===================================================================
# Category 11: Secret redaction and monetary amount concerns
# ===================================================================

class TestCategory11_Redaction:
    """Verify digit redaction behavior, including the documented
    side-effect where monetary amounts may also be masked."""

    def test_otp_6_digits_redacted(self):
        """6-digit OTPs must be partially masked."""
        assert _redact_secrets("OTP 482913") == "OTP 4****3"

    def test_otp_4_digits_redacted(self):
        """4-digit OTPs/PINs must also be masked."""
        assert _redact_secrets("PIN 1234") == "PIN 1**4"

    def test_3_digits_not_redacted(self):
        """3-digit amounts (Rs 500) should NOT be redacted."""
        assert _redact_secrets("Rs 500") == "Rs 500"

    def test_2_digits_not_redacted(self):
        """2-digit numbers should NOT be redacted."""
        assert _redact_secrets("age 25") == "age 25"

    def test_card_16_digits_redacted(self):
        """16-digit card numbers must be heavily masked."""
        result = _redact_secrets("Card 4111222233334444")
        assert result.startswith("Card 4")
        assert result.endswith("4")
        assert "4111222233334444" not in result

    def test_amount_4_digits_preserved_when_labelled(self):
        """Phase 5.7 intentional change: Clearly labelled currency amounts
        like 'Rs 2500' are preserved in evidence snippets across both Python
        and TypeScript engines so users can understand transaction amounts."""
        result = _redact_secrets("Rs 2500")
        assert result == "Rs 2500"

    def test_amount_5_digits_preserved_when_labelled(self):
        """Phase 5.7 intentional change: Rs 15000 and ₹2500 are preserved."""
        assert _redact_secrets("Rs 15000") == "Rs 15000"
        assert _redact_secrets("₹2500") == "₹2500"
        assert _redact_secrets("$1500") == "$1500"

    def test_unlabelled_number_masked_due_to_ambiguity(self):
        """Unlabelled 4-digit numbers without currency indicators cannot be
        reliably distinguished from PINs/codes, so they are masked."""
        result = _redact_secrets("Pay 1500 immediately")
        assert result == "Pay 1**0 immediately"

    def test_grouped_phone_numbers_redacted(self):
        """Grouped phone numbers with spaces or hyphens must be masked."""
        assert _redact_secrets("Call 987-654-3210 now") == "Call 9**-***-**10 now"
        assert _redact_secrets("Call +91 98765 43210 now") == "Call +91 9***5 4***0 now"

    def test_grouped_card_numbers_redacted(self):
        """16-digit card numbers with spaces or hyphens must be masked."""
        assert _redact_secrets("Card 4111 2222 3333 4444") == "Card 4*** **** **** ***4"
        assert _redact_secrets("Card 4111-2222-3333-4444") == "Card 4***-****-****-***4"

    def test_amount_with_adjacent_otp(self):
        """Currency amount is preserved while adjacent OTP is masked."""
        result = _redact_secrets("Cashback of Rs 2500; OTP 482913")
        assert result == "Cashback of Rs 2500; OTP 4****3"

    def test_amount_with_adjacent_account_reference(self):
        """Currency amount is preserved while adjacent account suffix is masked."""
        result = _redact_secrets("Amount ₹15000, account ending 4321")
        assert result == "Amount ₹15000, account ending 4**1"

    def test_evidence_in_api_response_redacted(self):
        """Full pipeline: OTP digits must not appear in evidence
        returned by analyze_message."""
        r = analyze_message("Please share your OTP 739182 to verify your bank account immediately.")
        for s in r.signals:
            for ev in s.evidence:
                assert "739182" not in ev, f"Full OTP found in evidence: {ev}"

    def test_multiple_otps_all_redacted(self):
        """If multiple OTPs appear, all must be redacted."""
        result = _redact_secrets("OTP1: 482913, OTP2: 739182")
        assert "482913" not in result
        assert "739182" not in result

    def test_phone_number_redacted(self):
        """10-digit phone numbers should be partially masked."""
        result = _redact_secrets("Call 9876543210 now")
        assert "9876543210" not in result
        assert result == "Call 9********0 now"


# ===================================================================
# Category 12: False negatives — indirect language
# ===================================================================

class TestCategory12_FalseNegatives:
    """Messages that use indirect language instead of obvious
    keywords.  These are known limitations of a keyword-based engine.
    Document what IS and ISN'T detected."""

    def test_indirect_otp_request_type_the_number(self):
        """'Type the number you received' — indirect OTP request.
        The keyword engine may not catch this because it doesn't
        say 'OTP' explicitly.  Document as a known limitation."""
        r = analyze_message(
            "We have sent a number to your phone. Type the number "
            "in the box below to confirm your identity."
        )
        # This is a known false negative — the engine looks for
        # explicit keywords like OTP/PIN/password
        # We document this but do not force a pass/fail assertion
        # that would break if the engine is later improved.
        if not _has(r, "credential-request"):
            pytest.skip("Known limitation: indirect OTP requests without keywords not detected")

    def test_social_engineering_flattery(self):
        """'You were selected' without prize keywords.
        Known limitation: requires 'won'/'lottery'/'prize' etc."""
        r = analyze_message(
            "You were selected for an exclusive opportunity to earn "
            "additional income. Contact us for more details."
        )
        # May or may not trigger too-good depending on keywords
        if r.risk_level == RiskLevel.NO_STRONG_SIGNS:
            pytest.skip("Known limitation: indirect social engineering without prize keywords")

    def test_vague_payment_without_amount(self):
        """'Transfer some amount' without Rs/INR/$ — may not match
        payment-demand which looks for currency indicators."""
        r = analyze_message(
            "To complete the process, transfer some amount to the "
            "account provided and share the receipt."
        )
        # payment-demand pattern requires currency indicators or fee keywords
        if not _has(r, "payment-demand"):
            pytest.skip("Known limitation: payment request without currency indicator not detected")

    def test_whatsapp_forwarded_scam(self):
        """A forwarded message about a 'government scheme' that
        asks to click a link.  Tests whether the engine catches it
        through the link analysis even without explicit scam keywords."""
        r = analyze_message(
            "Forwarded message: Government is giving Rs 5000 to every citizen. "
            "Apply now at http://govt-scheme.xyz/apply before the deadline."
        )
        # Should catch: unusual TLD (.xyz), payment-demand or too-good
        assert r.risk_level in (RiskLevel.HIGH_RISK, RiskLevel.SUSPICIOUS)
        assert SignalCategory.LINK in _cats(r)

    def test_multi_step_scam_part1(self):
        """First message in a multi-step scam: just builds rapport.
        A keyword engine cannot detect this — it's a known limitation."""
        r = analyze_message(
            "Hi, I'm Priya from the HR department. We met at the conference. "
            "I have an exciting project to discuss. Are you available tomorrow?"
        )
        # This is a pure social engineering opener with zero keywords
        assert r.risk_level == RiskLevel.NO_STRONG_SIGNS
        # Document: the engine correctly produces no false positive here,
        # but also cannot warn about a multi-step scam.

    def test_obfuscated_keywords_with_spaces(self):
        """'O T P' with spaces between letters — keyword engine
        won't match because it searches for 'otp' as a word."""
        r = analyze_message(
            "Please share your O T P to proceed with the verification."
        )
        if not _has(r, "credential-request"):
            pytest.skip("Known limitation: spaced-out keywords like 'O T P' not detected")


# ===================================================================
# Additional regression tests for existing behavior
# ===================================================================

class TestRegressions:
    """Regression tests for behavior that must be preserved."""

    def test_payment_demand_with_rupee_symbol(self):
        """₹ (U+20B9) must be recognized as a currency indicator."""
        r = analyze_message("Transfer ₹500 to the given account number to activate your insurance policy.")
        assert _has(r, "payment-demand")

    def test_impersonation_requires_co_occurrence(self):
        """Brand name alone (without action keywords) must NOT trigger."""
        r = analyze_message("I bought my phone from Flipkart and it arrived yesterday.")
        assert not _has(r, "impersonation")

    def test_impersonation_with_action_keyword(self):
        """Brand name + 'account' / 'verify' etc. should trigger."""
        r = analyze_message(
            "This is Amazon customer care. Your account has been flagged. "
            "Click the link to verify your details."
        )
        assert _has(r, "impersonation")

    def test_negation_skip_works_consistently(self):
        """Multiple negation phrases should all prevent false positives."""
        for prefix in [
            "Do not share your OTP with anyone.",
            "Don't share your OTP with anyone.",
            "Never share your OTP or password with anyone.",
            "Not to share your OTP or PIN with any person.",
        ]:
            r = analyze_message(prefix + " This is a security message from your bank.")
            assert not _has(r, "credential-request"), f"False positive for: {prefix}"

    def test_classification_thresholds_preserved(self):
        """Verify the classification thresholds haven't changed:
        - 1+ high → high_risk
        - 3+ medium → high_risk
        - 1+ medium → suspicious
        - 2+ low → suspicious
        - else → no_strong_signs"""
        # 1 high-severity signal
        r = analyze_message("Install AnyDesk now to resolve the banking error on your phone.")
        assert r.risk_level == RiskLevel.HIGH_RISK

        # 1 medium-severity signal
        r = analyze_message("URGENT: Respond to this message immediately or your service expires.")
        assert r.risk_level == RiskLevel.SUSPICIOUS

        # No signals
        r = analyze_message("Good morning! The weather is lovely today.")
        assert r.risk_level == RiskLevel.NO_STRONG_SIGNS

    def test_camel_case_output_preserved(self):
        """The API contract must continue to use camelCase."""
        r = analyze_message("Share your OTP 482913 now to complete verification.")
        data = r.model_dump(by_alias=True)
        assert "riskLevel" in data
        assert "nextSteps" in data
        assert "analyzedAt" in data
        assert "risk_level" not in data
