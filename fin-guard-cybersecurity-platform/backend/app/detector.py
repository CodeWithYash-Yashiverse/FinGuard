"""Rule-based scam-detection engine — Python port of ``lib/analysis/engine.ts``.

This module is intentionally **independent of FastAPI** so that it can be
tested without running a server.  Every regex rule and threshold has been
ported from the TypeScript original as faithfully as practical.

Behavioural alignment with TypeScript engine
---------------------------------------------------
* **Secret redaction** — sensitive digit sequences (OTPs, PINs, card numbers,
  phone numbers, references) inside evidence snippets are partially masked
  (e.g. ``482913`` → ``4****3``). Clearly labelled monetary amounts (such as
  "Rs 2500", "₹2500", "$1500") are preserved for readability.
  Both Python and TypeScript engines share this redaction behavior.
* **Unicode normalisation** — identical (NFKC).
* **Regex flavour** — Python ``re`` and JavaScript ``RegExp`` handle ``\\b``
  identically for ASCII text.  For non-ASCII word characters the two engines
  may disagree; in practice all rule patterns target ASCII keywords so the
  behaviour is equivalent.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from .schemas import (
    AnalysisEngineInfo,
    AnalysisResult,
    RiskLevel,
    Severity,
    SignalCategory,
    WarningSignal,
)

# ---------------------------------------------------------------------------
# Engine metadata
# ---------------------------------------------------------------------------

ENGINE_NAME = "FinGuard heuristic engine"
ENGINE_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Internal rule definition
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Rule:
    id: str
    category: SignalCategory
    title: str
    severity: Severity
    explanation: str
    patterns: tuple[re.Pattern[str], ...]
    requires: Optional[re.Pattern[str]] = None
    skip_if_preceded_by: Optional[re.Pattern[str]] = None


# ---------------------------------------------------------------------------
# Rules — ported from the TypeScript ``RULES`` array
# ---------------------------------------------------------------------------

_RULES: tuple[_Rule, ...] = (
    # 1. credential-request
    _Rule(
        id="credential-request",
        category=SignalCategory.CREDENTIALS,
        title="Asks you to share an OTP, PIN, or password",
        severity=Severity.HIGH,
        explanation=(
            "Banks, payment apps, and government agencies never ask you to "
            "share an OTP, UPI PIN, CVV, or password. Anyone who has these "
            "can move money out of your account."
        ),
        patterns=(
            re.compile(
                r"\b(share|send|tell|provide|give|forward|reply(?: with)?|"
                r"read out|confirm|sms)\b"
                r"[^.\n!?]{0,40}?"
                r"\b(otp|one[\s-]?time[\s-]?(?:password|passcode|code|pin)"
                r"|upi\s?pin|m-?pin|atm pin|cvv|cvc|password|passcode"
                r"|verification code|card number|card details)\b",
                re.IGNORECASE,
            ),
        ),
        skip_if_preceded_by=re.compile(
            r"\b(do not|don't|dont|never|not to|no one will)\s*$",
            re.IGNORECASE,
        ),
    ),
    # 2. pin-to-receive
    _Rule(
        id="pin-to-receive",
        category=SignalCategory.PAYMENT,
        title="Claims you need a PIN or QR scan to receive money",
        severity=Severity.HIGH,
        explanation=(
            "You never need to enter your UPI PIN, scan a QR code, or "
            "approve a request to receive money. Entering your PIN always "
            "sends money out of your account."
        ),
        patterns=(
            re.compile(
                r"\b(enter|input|type|use)\b[^.\n]{0,30}"
                r"\b(upi\s?)?pin\b[^.\n]{0,50}"
                r"\b(receive|get|claim|credit(?:ed)?|refund|cashback|prize)\b",
                re.IGNORECASE,
            ),
            re.compile(
                r"\b(receive|claim|get)\b[^.\n]{0,40}"
                r"\b(enter|scan|approve|accept)\b[^.\n]{0,30}"
                r"\b(pin|qr|request)\b",
                re.IGNORECASE,
            ),
            re.compile(
                r"\bscan\b[^.\n]{0,25}\bqr\b[^.\n]{0,50}"
                r"\b(receive|get|claim|refund|cashback|prize|credit)\b",
                re.IGNORECASE,
            ),
        ),
    ),
    # 3. remote-access
    _Rule(
        id="remote-access",
        category=SignalCategory.PATTERN,
        title="Asks you to install a screen-sharing or remote-access app",
        severity=Severity.HIGH,
        explanation=(
            "Remote-access apps let another person see and control your "
            "phone, including your banking apps and OTPs. Legitimate support "
            "teams do not need this to resolve payment issues."
        ),
        patterns=(
            re.compile(
                r"\b(anydesk|any desk|teamviewer|quick ?support|rustdesk"
                r"|airdroid|screen ?shar(?:e|ing)"
                r"|remote (?:access|control) app)\b",
                re.IGNORECASE,
            ),
        ),
    ),
    # 4. legal-threat
    _Rule(
        id="legal-threat",
        category=SignalCategory.URGENCY,
        title="Threatens arrest or legal action",
        severity=Severity.HIGH,
        explanation=(
            "Police, courts, and tax authorities do not demand payment over "
            'messages or calls, and there is no such thing as a "digital '
            'arrest". Fear is used to stop you from thinking clearly.'
        ),
        patterns=(
            re.compile(
                r"\b(digital arrest|arrest warrant|you will be arrested"
                r"|legal action will be"
                r"|fir (?:has been|will be) (?:filed|registered)"
                r"|case (?:has been )?registered against you"
                r"|money laundering case)\b",
                re.IGNORECASE,
            ),
        ),
    ),
    # 5. urgency
    _Rule(
        id="urgency",
        category=SignalCategory.URGENCY,
        title="Creates pressure to act immediately",
        severity=Severity.MEDIUM,
        explanation=(
            "Scammers rush you so you act before verifying. A genuine "
            "organisation will give you time to check through official "
            "channels."
        ),
        patterns=(
            re.compile(
                r"\b(urgent(?:ly)?|immediately|right away|asap|act now"
                r"|last (?:chance|warning|reminder)"
                r"|final (?:notice|warning|reminder)"
                r"|within \d+\s?(?:min(?:ute)?s?|hours?|hrs?)"
                r"|today itself|before midnight"
                r"|expir(?:es|ing) (?:today|tonight|soon|in))\b",
                re.IGNORECASE,
            ),
        ),
    ),
    # 6. account-threat
    _Rule(
        id="account-threat",
        category=SignalCategory.URGENCY,
        title="Warns that your account or service will be blocked",
        severity=Severity.MEDIUM,
        explanation=(
            "Messages claiming your account, card, SIM, or KYC will be "
            "blocked are a common way to push people into clicking links or "
            "sharing details."
        ),
        patterns=(
            re.compile(
                r"\b(account|a/c|card|kyc|sim|mobile number|connection"
                r"|electricity|power|wallet|pan)\b"
                r"[^.\n]{0,40}"
                r"\b(block(?:ed)?|suspend(?:ed)?|deactivat(?:e|ed)"
                r"|frozen|freeze|disconnect(?:ed)?|terminat(?:e|ed)"
                r"|on hold)\b",
                re.IGNORECASE,
            ),
            re.compile(
                r"\bkyc\b[^.\n]{0,20}"
                r"\b(update|pending|expired|incomplete|verification)\b",
                re.IGNORECASE,
            ),
        ),
    ),
    # 7. payment-demand
    _Rule(
        id="payment-demand",
        category=SignalCategory.PAYMENT,
        title="Requests a payment, fee, or approval",
        severity=Severity.MEDIUM,
        explanation=(
            "Unexpected requests to pay a fee, deposit, or \"release\" "
            "charge are a hallmark of prize, job, delivery, and loan scams. "
            "Verify any request for money independently."
        ),
        patterns=(
            re.compile(
                r"\b(pay|transfer|deposit|send)\b[^.\n]{0,30}"
                r"(\u20b9|\brs\.?|\binr\b|\brupees\b|\$|\busd\b"
                r"|\bamount\b|\bfee\b|\bcharges?\b)",
                re.IGNORECASE,
            ),
            re.compile(
                r"\b(processing|registration|release|clearance|customs"
                r"|security|refundable|verification|delivery)"
                r"\s+(fee|charges?|deposit)\b",
                re.IGNORECASE,
            ),
            re.compile(
                r"\b(collect request|approve (?:the )?(?:payment )?request"
                r"|accept (?:the )?payment request)\b",
                re.IGNORECASE,
            ),
        ),
    ),
    # 8. too-good
    _Rule(
        id="too-good",
        category=SignalCategory.PATTERN,
        title="Offers a prize, refund, or income that seems too good",
        severity=Severity.MEDIUM,
        explanation=(
            "Unexpected winnings, cashback, refunds, or easy-income offers "
            "are used to lower your guard before asking for a fee or your "
            "details."
        ),
        patterns=(
            re.compile(
                r"\b(you(?:'ve| have)? won|winner|lottery|lucky draw"
                r"|jackpot|claim (?:your )?(?:prize|reward|gift)"
                r"|free gift|reward points? (?:expir\w*|redeem\w*))\b",
                re.IGNORECASE,
            ),
            re.compile(
                r"\b(work from home|part[- ]time job"
                r"|earn\s*(?:\u20b9|rs\.?|inr)?\s?\d[\d,]*\s*"
                r"(?:per|/|a|daily)\s*(?:day|hour|task)?"
                r"|like (?:videos|youtube videos)"
                r"|daily (?:income|payout)|task[- ]based)\b",
                re.IGNORECASE,
            ),
        ),
    ),
    # 9. impersonation
    _Rule(
        id="impersonation",
        category=SignalCategory.IMPERSONATION,
        title="Claims to be from a bank, payment app, or authority",
        severity=Severity.MEDIUM,
        explanation=(
            "Anyone can put a bank, brand, or government name in a message. "
            "A claim of identity is not proof of identity \u2014 confirm it "
            "using contact details you find yourself."
        ),
        patterns=(
            re.compile(
                r"\b(sbi|state bank|hdfc|icici|axis bank|kotak|pnb"
                r"|bank of baroda|rbi|reserve bank|npci"
                r"|paytm|phonepe|phone pe|google pay|gpay|bhim"
                r"|amazon|flipkart|income tax|customs|cbi|police"
                r"|cyber cell|trai|fedex|dhl|india post|courier"
                r"|electricity board|customer care"
                r"|bank manager|bank official)\b",
                re.IGNORECASE,
            ),
        ),
        requires=re.compile(
            r"\b(account|kyc|refund|verify|verification|update|block"
            r"|suspend|officer|department|parcel|bill|reward|cashback"
            r"|pending|link|click)\b",
            re.IGNORECASE,
        ),
    ),
    # 10. secrecy
    _Rule(
        id="secrecy",
        category=SignalCategory.PATTERN,
        title="Asks you to keep the conversation secret",
        severity=Severity.MEDIUM,
        explanation=(
            "Being told not to tell family or your bank, or to stay on the "
            "call, is a pressure tactic designed to stop someone from "
            "warning you."
        ),
        patterns=(
            re.compile(
                r"\b(don'?t tell (?:anyone|your family|your bank)"
                r"|do not (?:tell|inform) (?:anyone|your family|your bank)"
                r"|keep (?:this|it) (?:confidential|secret)"
                r"|don'?t (?:disconnect|hang up)"
                r"|stay on the (?:call|line))\b",
                re.IGNORECASE,
            ),
        ),
    ),
    # 11. callback-number
    _Rule(
        id="callback-number",
        category=SignalCategory.IMPERSONATION,
        title="Asks you to call or message an unverified number",
        severity=Severity.LOW,
        explanation=(
            "Numbers inside a suspicious message may connect you directly "
            "to the scammer. Use the number printed on your card or the "
            "official website instead."
        ),
        patterns=(
            re.compile(
                r"\b(call|whatsapp|contact|dial|message)\b"
                r"[^.\n]{0,30}"
                r"(\+?\d[\d\s-]{8,}\d)",
                re.IGNORECASE,
            ),
        ),
    ),
)

# ---------------------------------------------------------------------------
# Link-analysis constants — ported from the TypeScript module
# ---------------------------------------------------------------------------

_URL_PATTERN = re.compile(
    r"\b((?:https?://|www\.)[^\s<>\"']+|"
    r"[a-z0-9-]+(?:\.[a-z0-9-]+)*\."
    r"(?:com|in|net|org|xyz|top|click|live|online|info|icu|buzz|site"
    r"|me|ly|co|io|app|link|shop|vip|cc|tk|ml|ga|cf|gq)"
    r"(?:/[^\s<>\"']*)?)",
    re.IGNORECASE,
)

_TRAILING_PUNCT = re.compile(r"[),.;:!?'\"\]]+$")

_SHORTENERS: frozenset[str] = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "cutt.ly",
        "rb.gy",
        "ow.ly",
        "shorturl.at",
        "tiny.cc",
        "s.id",
        "v.gd",
        "rebrand.ly",
    }
)

_UNUSUAL_TLDS: frozenset[str] = frozenset(
    {
        "xyz", "top", "click", "live", "online", "info", "icu", "buzz",
        "site", "vip", "shop", "cc", "tk", "ml", "ga", "cf", "gq", "link",
    }
)

_BRAND_DOMAINS: dict[str, list[str]] = {
    "sbi": ["sbi.co.in", "onlinesbi.sbi", "sbi.bank.in", "sbicard.com"],
    "hdfc": ["hdfcbank.com", "hdfc.bank.in"],
    "icici": ["icicibank.com", "icici.bank.in"],
    "axis": ["axisbank.com", "axis.bank.in"],
    "kotak": ["kotak.com"],
    "paytm": ["paytm.com"],
    "phonepe": ["phonepe.com"],
    "gpay": ["google.com", "pay.google.com"],
    "amazon": ["amazon.in", "amazon.com"],
    "flipkart": ["flipkart.com"],
    "npci": ["npci.org.in"],
    "rbi": ["rbi.org.in"],
    "incometax": ["incometax.gov.in"],
    "indiapost": ["indiapost.gov.in"],
}

_SEVERITY_WEIGHT: dict[Severity, int] = {
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
}

# ---------------------------------------------------------------------------
# Verification guidance — static, identical to TypeScript ``VERIFICATION_GUIDANCE``
# ---------------------------------------------------------------------------

_VERIFICATION_GUIDANCE: list[str] = [
    (
        "Find the organisation\u2019s contact details yourself \u2014 the "
        "back of your card, your official banking app, or a website address "
        "you type manually."
    ),
    (
        "Never use phone numbers, links, or QR codes provided inside the "
        "suspicious message."
    ),
    (
        "Check the transaction or request inside your official bank or UPI "
        "app, not through a link."
    ),
    (
        "Remember: receiving money never requires your PIN, an OTP, or "
        "scanning a QR code."
    ),
]


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Redaction helpers — aligned with TypeScript ``redactSecrets()``
# ---------------------------------------------------------------------------

_CURRENCY_PATTERN = re.compile(
    r"(?:(?:₹|\brs\.?|\binr\b|\brupees\b|\$|\busd\b|\beur\b|€|£|\bgbp\b)\s*[\d,]+(?:\.\d+)?|"
    r"[\d,]+(?:\.\d+)?\s*(?:₹|\brs\.?|\binr\b|\brupees\b|\$|\busd\b|\beur\b|€|£|\bgbp\b|\/-|"
    r"\/(?:day|hour|month|year)\b|\bper\s+(?:day|hour|month|year|task)\b))",
    re.IGNORECASE,
)

_CARD_GROUPED_PATTERN = re.compile(
    r"\b(\d{4})([-\s])(\d{4})([-\s])(\d{4})([-\s])(\d{4})\b"
)
_PHONE_GROUPED_PATTERN = re.compile(
    r"\b(\d{3})([-\s])(\d{3})([-\s])(\d{4})\b"
)


def _redact_secrets(text: str) -> str:
    """Partially mask sensitive numeric sequences in evidence snippets.

    Prevents full OTPs, PINs, card numbers, phone numbers and long reference
    numbers from being displayed in evidence excerpts while preserving ordinary
    monetary amounts (e.g. "Rs 1500", "₹2500", "$1500") when clearly formatted
    as currency.
    """
    if not text or not isinstance(text, str):
        return text

    # 1. Identify currency amount spans to protect them from redaction
    currency_spans = [
        (m.start(), m.end()) for m in _CURRENCY_PATTERN.finditer(text)
    ]

    def _is_currency(start: int, end: int) -> bool:
        return any(c_start <= start and end <= c_end for c_start, c_end in currency_spans)

    # 2. Formatted 16-digit card numbers (e.g. 4111 2222 3333 4444 or 4111-2222-3333-4444)
    def _mask_card(m: re.Match[str]) -> str:
        if _is_currency(m.start(), m.end()):
            return m.group(0)
        g1, s1, _g2, s2, _g3, s3, g4 = m.groups()
        return f"{g1[0]}***{s1}****{s2}****{s3}***{g4[3]}"

    out = _CARD_GROUPED_PATTERN.sub(_mask_card, text)

    # 3. Formatted 10-digit phone numbers with 3-3-4 pattern (e.g. 987-654-3210 or 987 654 3210)
    def _mask_phone(m: re.Match[str]) -> str:
        if _is_currency(m.start(), m.end()):
            return m.group(0)
        g1, s1, _g2, s2, g3 = m.groups()
        return f"{g1[0]}**{s1}***{s2}**{g3[-2:]}"

    out = _PHONE_GROUPED_PATTERN.sub(_mask_phone, out)

    # 4. Standalone 4+ digit sequences (OTPs, PINs, unspaced cards, refs, phone blocks)
    def _mask_digits(m: re.Match[str]) -> str:
        if _is_currency(m.start(), m.end()):
            return m.group(0)
        d = m.group(0)
        return d[0] + "*" * (len(d) - 2) + d[-1]

    out = re.sub(r"\d{4,}", _mask_digits, out)

    return out


def _snippet(text: str, index: int, length: int) -> str:
    """Extract a short evidence excerpt around a match, with redaction.

    Mirrors the TypeScript ``snippet()`` helper: ±28 chars of padding,
    whitespace collapsed, ellipsis markers at truncation boundaries.
    """
    pad = 28
    start = max(0, index - pad)
    end = min(len(text), index + length + pad)
    out = re.sub(r"\s+", " ", text[start:end]).strip()
    if start > 0:
        out = f"\u2026{out}"
    if end < len(text):
        out = f"{out}\u2026"
    return _redact_secrets(out)


def _run_rule(rule: _Rule, text: str) -> WarningSignal | None:
    """Evaluate a single rule against *text* and return a signal or ``None``."""
    if rule.requires is not None and not rule.requires.search(text):
        return None

    evidence: set[str] = set()

    for pattern in rule.patterns:
        for match in pattern.finditer(text):
            index = match.start()
            # False-positive guard: skip if preceded by negation
            if rule.skip_if_preceded_by is not None:
                before = text[max(0, index - 24) : index]
                if rule.skip_if_preceded_by.search(before):
                    continue
            evidence.add(_snippet(text, index, len(match.group(0))))
            if len(evidence) >= 3:
                break
        if len(evidence) >= 3:
            break

    if not evidence:
        return None

    return WarningSignal(
        id=rule.id,
        category=rule.category,
        title=rule.title,
        severity=rule.severity,
        explanation=rule.explanation,
        evidence=list(evidence),
    )


# ---------------------------------------------------------------------------
# Link analysis — ported from ``analyzeLinks()``
# ---------------------------------------------------------------------------


def _host_of(raw: str) -> str | None:
    """Extract the hostname from a raw URL string.  Never fetches the URL."""
    cleaned = _TRAILING_PUNCT.sub("", raw)
    if not re.match(r"^https?://", cleaned, re.IGNORECASE):
        cleaned = f"http://{cleaned}"
    try:
        parsed = urlparse(cleaned)
        hostname = parsed.hostname
        return hostname.lower() if hostname else None
    except Exception:
        return None


def _matches_domain(host: str, domain: str) -> bool:
    return host == domain or host.endswith(f".{domain}")


def _analyze_links(text: str) -> list[WarningSignal]:
    """Detect suspicious link characteristics using safe text parsing only.

    URLs are **never** opened, fetched, or resolved.
    """
    raw_links = [
        _TRAILING_PUNCT.sub("", m.group(0))
        for m in _URL_PATTERN.finditer(text)
    ]
    if not raw_links:
        return []

    # Accumulator: id → (severity, title, explanation, evidence set)
    findings: dict[
        str,
        dict,
    ] = {}

    def _add(
        finding_id: str,
        severity: Severity,
        title: str,
        explanation: str,
        link: str,
    ) -> None:
        if finding_id not in findings:
            findings[finding_id] = {
                "severity": severity,
                "title": title,
                "explanation": explanation,
                "evidence": set(),
            }
        ev: set[str] = findings[finding_id]["evidence"]
        if len(ev) < 3:
            ev.add(link)

    for link in raw_links:
        host = _host_of(link)
        if host is None:
            continue
        bare_host = re.sub(r"^www\.", "", host)
        tld = bare_host.rsplit(".", 1)[-1] if "." in bare_host else ""

        # Raw IP address
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", bare_host):
            _add(
                "link-ip",
                Severity.HIGH,
                "Link points to a raw IP address",
                "Legitimate banks and payment services use named domains. "
                "A link made of numbers hides who operates the site.",
                link,
            )

        # Punycode / IDN look-alike
        if "xn--" in bare_host:
            _add(
                "link-punycode",
                Severity.HIGH,
                "Link uses look-alike characters",
                "This domain uses encoded characters that can imitate a "
                "familiar brand name letter for letter.",
                link,
            )

        # URL shortener
        if any(_matches_domain(bare_host, s) for s in _SHORTENERS):
            _add(
                "link-shortener",
                Severity.MEDIUM,
                "Shortened link hides the real destination",
                "Link shorteners conceal where you will actually land. "
                "Payment providers rarely send shortened links for account "
                "actions.",
                link,
            )

        # Unusual TLD
        if tld in _UNUSUAL_TLDS:
            _add(
                "link-tld",
                Severity.MEDIUM,
                "Link uses an unusual domain ending",
                f'Domains ending in ".{tld}" are cheap to register and are '
                f"frequently used for short-lived scam sites.",
                link,
            )

        # Brand look-alike
        flat_host = re.sub(r"[-.]", "", bare_host)
        for brand, domains in _BRAND_DOMAINS.items():
            if brand in flat_host and not any(
                _matches_domain(bare_host, d) for d in domains
            ):
                _add(
                    "link-lookalike",
                    Severity.HIGH,
                    "Link imitates a known brand but is not its official "
                    "domain",
                    f'The address mentions "{brand}" but is not an official '
                    f"{brand.upper()} domain. Look-alike sites are built to "
                    f"collect login details and card numbers.",
                    link,
                )
                break

        # Insecure (plain HTTP)
        if re.match(r"^http://", link, re.IGNORECASE):
            _add(
                "link-insecure",
                Severity.LOW,
                "Link is not encrypted",
                "This link uses http instead of https. A payment or login "
                "page should never be served without encryption.",
                link,
            )

    # Build signal list from findings
    signals: list[WarningSignal] = [
        WarningSignal(
            id=fid,
            category=SignalCategory.LINK,
            title=f["title"],
            severity=f["severity"],
            explanation=f["explanation"],
            evidence=list(f["evidence"]),
        )
        for fid, f in findings.items()
    ]

    # Fallback: link is present but nothing specific is wrong
    if not signals:
        signals.append(
            WarningSignal(
                id="link-present",
                category=SignalCategory.LINK,
                title="Contains a link",
                severity=Severity.LOW,
                explanation=(
                    "No specific problem was found with this link, but links "
                    "in unexpected payment messages should not be trusted. "
                    "Type the official address yourself instead."
                ),
                evidence=raw_links[:3],
            )
        )

    return signals


# ---------------------------------------------------------------------------
# Classification — ported from ``classify()``
# ---------------------------------------------------------------------------


def _classify(signals: list[WarningSignal]) -> RiskLevel:
    """Map signal counts to a risk level using the same thresholds as TS."""
    high = sum(1 for s in signals if s.severity == Severity.HIGH)
    medium = sum(1 for s in signals if s.severity == Severity.MEDIUM)
    low = sum(1 for s in signals if s.severity == Severity.LOW)

    if high >= 1 or medium >= 3:
        return RiskLevel.HIGH_RISK
    if medium >= 1 or low >= 2:
        return RiskLevel.SUSPICIOUS
    return RiskLevel.NO_STRONG_SIGNS


# ---------------------------------------------------------------------------
# Summary and next-steps builders
# ---------------------------------------------------------------------------


def _build_summary(level: RiskLevel, signals: list[WarningSignal]) -> str:
    n = len(signals)
    plural = "sign" if n == 1 else "signs"

    if level == RiskLevel.HIGH_RISK:
        return (
            f"We found {n} warning {plural}, including patterns strongly "
            f"associated with payment scams. Do not act on this message "
            f"until you have verified it independently."
        )
    if level == RiskLevel.SUSPICIOUS:
        return (
            f"We found {n} warning {plural} that are common in scam "
            f"messages. This is not proof of fraud, but the message "
            f"deserves caution and independent verification."
        )
    # no_strong_signs
    if n > 0:
        return (
            "We did not find strong warning signs, only a minor indicator. "
            "This does not mean the message is safe \u2014 verify any request "
            "for money or information through official channels."
        )
    return (
        "We did not find strong warning signs. This does not mean the "
        "message is safe \u2014 some scams contain no obvious indicators. "
        "Verify any request for money or information through official "
        "channels."
    )


def _build_next_steps(
    level: RiskLevel, signals: list[WarningSignal]
) -> list[str]:
    ids = {s.id for s in signals}
    categories = {s.category for s in signals}
    steps: list[str] = []

    if "credential-request" in ids:
        steps.append(
            "Do not share any OTP, UPI PIN, CVV, or password \u2014 with "
            "anyone, for any reason."
        )
    if "pin-to-receive" in ids or "payment-demand" in ids:
        steps.append(
            "Do not send money, enter your PIN, scan the QR code, or "
            "approve any collect request from this message."
        )
    if SignalCategory.LINK in categories:
        steps.append(
            "Do not open the link. If you need to check your account, type "
            "the official website address yourself or use the official app."
        )
    if "remote-access" in ids:
        steps.append(
            "Do not install any app the sender recommends. If you already "
            "did, uninstall it and change your banking passwords from a "
            "different device."
        )
    if "legal-threat" in ids or "secrecy" in ids:
        steps.append(
            "End the conversation. Talk to someone you trust before doing "
            "anything \u2014 real authorities will not object."
        )
    if level == RiskLevel.HIGH_RISK:
        steps.append(
            "If you already shared details or sent money, call your bank "
            "immediately using the number on your card or their official "
            "website, and ask them to block the transaction."
        )
        steps.append(
            "Report the message to your national cybercrime reporting "
            "service (see Safety & Reporting below)."
        )
    if level == RiskLevel.SUSPICIOUS:
        steps.append(
            "Pause before responding. Contact the organisation through a "
            "phone number or website you find independently."
        )
    if level == RiskLevel.NO_STRONG_SIGNS:
        steps.append(
            "If the message asks for money or personal information, still "
            "confirm it through official channels before acting."
        )

    return steps


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def analyze_message(message: str) -> AnalysisResult:
    """Run the rule-based detection engine on *message* and return a result.

    The function is **pure** (no network I/O, no file I/O, no side-effects).
    It never opens, fetches, or follows URLs found in the message.
    Raw message content is not logged or persisted.

    Parameters
    ----------
    message:
        The user-submitted text to analyse.  May be empty or whitespace-only;
        the function handles both gracefully (returns ``no_strong_signs``).
    """
    text = unicodedata.normalize("NFKC", message)
    signals: list[WarningSignal] = []

    # Run pattern rules
    for rule in _RULES:
        signal = _run_rule(rule, text)
        if signal is not None:
            signals.append(signal)

    # Run link analysis
    signals.extend(_analyze_links(text))

    # Sort by severity (high → low), matching TypeScript behaviour
    signals.sort(key=lambda s: _SEVERITY_WEIGHT.get(s.severity, 0), reverse=True)

    risk_level = _classify(signals)

    return AnalysisResult(
        risk_level=risk_level,
        summary=_build_summary(risk_level, signals),
        signals=signals,
        next_steps=_build_next_steps(risk_level, signals),
        verification=list(_VERIFICATION_GUIDANCE),
        engine=AnalysisEngineInfo(
            name=ENGINE_NAME,
            version=ENGINE_VERSION,
            mode="local",
        ),
        analyzed_at=datetime.now(timezone.utc).isoformat(),
    )
