"""Indian mobile numbers without a context word - for chat only.

Presidio's own PhoneRecognizer scores a valid number 0.4, below this
project's 0.5 threshold, and only a few context words lift it ("phone",
"mobile", "number" - "call" did not in testing). So in chat, "call me on
9876543210", "whatsapp 9876543210" and "+91 98765 43210" all went to the
model in the clear. Documents keep that context-scoped behavior on
purpose: a bank statement is full of 10-digit reference numbers.

This recognizer emits its own entity type, IN_MOBILE, so that only the
`chat` allow-list requests it. detect/analyzer.py reports it as
PHONE_NUMBER, so the codes and counts a caller sees don't change and a
number caught by both recognizers gets one code, not two.

Pattern: an optional +91 / 91 / 0 prefix, then a mobile number starting
6-9, as 10 digits or 5-5 with a space or hyphen ("98765 43210",
"98765-43210", "+91 98765 43210"). Guards, each against something
observed or likely:
- no letter, digit, "+" or "/" directly before it, and no letter or digit
  directly after: so not part of a longer digit run, an alphanumeric
  reference ("TXN9876543210") or a slash-separated reference
  ("UPI/9876543210");
- no digit before it through a comma or period, and no ".digit" after it:
  so not part of an amount ("12,50,000", "9876543210.50").
"""

from __future__ import annotations

from presidio_analyzer import Pattern, PatternRecognizer

_MOBILE = (
    r"(?<![\w+/])(?<!\d[.,])"
    r"(?:(?:\+91|91)[ \-]?|0)?"
    r"[6-9]\d{4}[ \-]?\d{5}"
    r"(?![\w])(?!\.\d)"
)


class IndianMobileRecognizer(PatternRecognizer):
    """IN_MOBILE (reported as PHONE_NUMBER): 0.6, masked with no context
    word. The context words only raise the score further."""

    PATTERNS = [Pattern("Indian mobile number", _MOBILE, 0.6)]
    # Single words, given as spaCy lemmas (see other_documents.py).
    CONTEXT = ["mobile", "phone", "number", "whatsapp", "contact", "ph", "tel", "reach", "call"]

    def __init__(self):
        super().__init__(
            supported_entity="IN_MOBILE",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            name="IndianMobileRecognizer",
        )
