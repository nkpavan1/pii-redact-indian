"""IFSC, UPI ID, bank account number, demat/DP ID.

Bank account and demat/DP numbers have no fixed national format, so unlike
IFSC/GSTIN/PAN these rely on a low base score plus strong context-word
matching rather than a distinctive regex shape - see per-class notes for the
specific collision risks that follow from that.

CONTEXT lists are single words only, never multi-word phrases - verified
directly (not assumed) that Presidio's context matcher checks individual
lemmatized tokens in the surrounding window, so a phrase like "account
number" as one context-list entry never matches anything (the doc tokenizes
it as two separate tokens "account" and "number"); it silently sat there
doing nothing until an end-to-end smoke test's score output exposed it (see
detect/recognizers/__init__.py's note on the credit-card collision found
the same way).
"""

from __future__ import annotations

from presidio_analyzer import Pattern, PatternRecognizer


class IfscRecognizer(PatternRecognizer):
    """Detects: IFSC code (4-letter bank code + literal '0' + 6-char branch
    code). FP/FN risk: low - the fixed '0' in position 5 is fairly
    distinctive. No checksum digit exists in the IFSC spec."""

    PATTERNS = [Pattern("IFSC (format)", r"\b[A-Z]{4}0[A-Z0-9]{6}\b", 0.7)]
    CONTEXT = ["ifsc", "code", "branch"]

    def __init__(self):
        super().__init__(
            supported_entity="IFSC",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            name="IfscRecognizer",
        )


class UpiIdRecognizer(PatternRecognizer):
    """Detects: UPI VPA (virtual payment address), e.g. `name@okaxis`.
    FP/FN risk: HIGH overlap with Presidio's built-in EMAIL_ADDRESS
    recognizer - a UPI handle and an email local-part are syntactically
    similar. The pattern here excludes a dot in the domain part (UPI PSP
    handles like `okaxis`/`ybl`/`paytm` never contain one, real email
    domains almost always do), which cuts most of the overlap but not all
    (some email providers use dotless domains on intranets). Presidio's
    conflict-resolution will pick whichever recognizer scores higher for a
    given span; don't assume this recognizer's output is mutually exclusive
    with EMAIL_ADDRESS without testing overlapping cases."""

    PATTERNS = [
        Pattern("UPI ID (format)", r"\b[\w.+-]{2,256}@[a-zA-Z]{2,64}\b(?!\.[a-zA-Z])", 0.4)
    ]
    CONTEXT = ["upi", "vpa", "gpay", "phonepe", "paytm"]

    def __init__(self):
        super().__init__(
            supported_entity="UPI_ID",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            name="UpiIdRecognizer",
        )


class BankAccountNumberRecognizer(PatternRecognizer):
    """Detects: bank account number (9-18 digit run). FP/FN risk: VERY HIGH
    without context - this is deliberately given a low base score (0.15,
    below any reasonable action threshold) and depends entirely on nearby
    context words to become actionable. Collides in length with Aadhaar
    (12 digits), UAN (12 digits), demat CDSL IDs (16 digits), and card
    numbers (13-19 digits) - do not raise the base score without also
    tightening context requirements, or this will fire on everything."""

    PATTERNS = [Pattern("Digit run 9-18 (context required)", r"\b\d{9,18}\b", 0.15)]
    CONTEXT = ["account", "acc", "bank"]

    def __init__(self):
        super().__init__(
            supported_entity="BANK_ACCOUNT_NUMBER",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            name="BankAccountNumberRecognizer",
        )


class DematDpIdRecognizer(PatternRecognizer):
    """Detects: demat/DP ID. NSDL format is distinctive ('IN' + 14 digits);
    CDSL format is a bare 16-digit number and is NOT distinguishable from a
    payment card number by shape alone, so that pattern is context-scoped
    with a low base score like BANK_ACCOUNT_NUMBER. FP/FN risk: NSDL pattern
    is low-risk; CDSL pattern is high-risk without context, by design."""

    PATTERNS = [
        Pattern("NSDL demat (format)", r"\bIN\d{14}\b", 0.7),
        Pattern("CDSL demat (context required)", r"\b\d{16}\b", 0.15),
    ]
    CONTEXT = ["demat", "dp", "depository", "participant", "client", "beneficiary"]

    def __init__(self):
        super().__init__(
            supported_entity="DEMAT_DP_ID",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            name="DematDpIdRecognizer",
        )
