"""EPF/UAN, CKYC number, mutual fund folio number - all context-scoped,
none has a public checksum algorithm to validate against.

CONTEXT lists are single words only - see banking.py's module docstring
for why (multi-word phrases don't match Presidio's context matcher at all).
"""

from __future__ import annotations

from presidio_analyzer import Pattern, PatternRecognizer


class EpfUanRecognizer(PatternRecognizer):
    """Detects: EPFO Universal Account Number (12 digits). FP/FN risk: the
    12-digit shape is IDENTICAL to Aadhaar's - without strong context this
    will either double-fire alongside IN_AADHAAR or get suppressed by
    Presidio's overlap resolution in an unpredictable way. Context words are
    load-bearing here, not optional. No checksum exists for UAN."""

    PATTERNS = [Pattern("UAN (context required)", r"\b\d{12}\b", 0.15)]
    CONTEXT = ["uan", "universal", "epf", "epfo", "provident", "fund"]

    def __init__(self):
        super().__init__(
            supported_entity="EPF_UAN",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            name="EpfUanRecognizer",
        )


class CkycNumberRecognizer(PatternRecognizer):
    """Detects: CKYC Identification Number / KIN (14 digits). FP/FN risk:
    moderate - 14-digit runs are less common than 12/16-digit ones but still
    not unique to CKYC; context-scoped accordingly. No public checksum."""

    PATTERNS = [Pattern("CKYC KIN (context required)", r"\b\d{14}\b", 0.2)]
    CONTEXT = ["ckyc", "kin", "kyc", "identification", "central"]

    def __init__(self):
        super().__init__(
            supported_entity="CKYC_NUMBER",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            name="CkycNumberRecognizer",
        )


class MutualFundFolioRecognizer(PatternRecognizer):
    """Detects: mutual fund folio number. FP/FN risk: HIGH - AMC-specific
    format, no national standard (seen as anything from a bare 8-12 digit
    number to `123456/78` with a slash). This pattern is intentionally broad
    and entirely context-dependent; expect to revisit once real (synthetic)
    sample statements are available to tighten it."""

    PATTERNS = [
        Pattern(
            "Folio number (context required)",
            r"\b\d{6,12}(?:/\d{1,4})?\b",
            0.15,
        )
    ]
    CONTEXT = ["folio", "number"]

    def __init__(self):
        super().__init__(
            supported_entity="MF_FOLIO_NUMBER",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            name="MutualFundFolioRecognizer",
        )
