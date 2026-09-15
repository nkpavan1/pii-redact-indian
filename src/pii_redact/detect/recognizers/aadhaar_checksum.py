"""Verhoeff-validated Aadhaar recognizer.

Per the project instructions ("Aadhaar/PAN precision"): Presidio's built-in
IN_AADHAAR recognizer confirms format only, not the Verhoeff check digit.
This recognizer matches the same 12-digit shape but adds a checksum pass via
validate_result, so registration in analyzer.py should REPLACE the built-in
IN_AADHAAR recognizer with this one, not add both - stacking them would
double-detect every match under the same entity type.
"""

from __future__ import annotations

from presidio_analyzer import Pattern, PatternRecognizer

from pii_redact.detect.checksum import verhoeff_is_valid


class AadhaarChecksumRecognizer(PatternRecognizer):
    """Detects: Aadhaar number (12 digits, optionally space-grouped as
    4-4-4), filtered by Verhoeff checksum. FP/FN risk: LOW after checksum
    validation - a random 12-digit run passes Verhoeff only ~10% of the
    time. Collides in raw shape with EPF/UAN (see kyc_and_scheme_ids.py) -
    the checksum filter is what actually disambiguates them in practice,
    since UAN has no checksum and will fail this validator most of the
    time. Checksum validation: yes (Verhoeff). Because validate_result always
    returns a definite True/False, Presidio forces the score to MAX (1.0) or
    MIN (0) regardless of context - the CONTEXT list below has no actual
    effect on this particular recognizer's behavior, but is still listed
    (as single words, not phrases - see banking.py's module docstring) for
    consistency and in case validate_result's behavior ever changes."""

    PATTERNS = [
        Pattern("Aadhaar (format)", r"\b\d{4}\s?\d{4}\s?\d{4}\b", 0.3)
    ]
    CONTEXT = ["aadhaar", "aadhar", "uidai", "unique", "identification"]

    def __init__(self):
        super().__init__(
            supported_entity="IN_AADHAAR",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            name="AadhaarChecksumRecognizer",
        )

    def validate_result(self, pattern_text: str) -> bool | None:
        digits_only = "".join(c for c in pattern_text if c.isdigit())
        return verhoeff_is_valid(digits_only)
