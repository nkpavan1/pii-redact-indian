"""Driving license, ITR acknowledgement number, ration card number - all
state-issued or year-varying formats without a single national pattern.

CONTEXT lists are single words only - see banking.py's module docstring
for why (multi-word phrases don't match Presidio's context matcher at all)
- AND each word must be given as its LEMMA, not necessarily its usual
surface form: Presidio compares context-list entries as literal strings
against the LEMMA of each nearby document token, so a gerund like
"driving" or "filing" never matches (spaCy lemmatizes them to "drive" and
"file" respectively) - verified directly, not assumed, same way the
"born" -> "bear" mismatch was found in dates.py. Check any new context
word's lemma with spaCy before adding it.
"""

from __future__ import annotations

from presidio_analyzer import Pattern, PatternRecognizer


class DrivingLicenseRecognizer(PatternRecognizer):
    """Detects: Indian driving license number, common format `SSRR YYYY
    NNNNNNN` (2-letter state + 2-digit RTO code + 4-digit year + 7-digit
    serial), with optional spaces/hyphens. FP/FN risk: HIGH - state RTOs
    have historically issued non-conforming formats, especially pre-2000.
    This pattern will miss older/irregular licenses (FN) and is specific
    enough that FP risk is low. No checksum."""

    PATTERNS = [
        Pattern(
            "Driving license (common format)",
            r"\b[A-Z]{2}[- ]?\d{2}[- ]?\d{4}[- ]?\d{7}\b",
            0.5,
        )
    ]
    CONTEXT = ["drive", "licence", "license", "dl", "number"]  # "drive", not "driving" - see module docstring

    def __init__(self):
        super().__init__(
            supported_entity="DRIVING_LICENSE",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            name="DrivingLicenseRecognizer",
        )


class PassportNumberRecognizer(PatternRecognizer):
    """Detects: Indian passport number, one letter + 7 digits (an optional
    space after the third character, as Presidio allows). Context-scoped
    like this project's other bare-format IDs: 0.15 alone, 0.5 with
    "passport" nearby.

    REPLACES Presidio's InPassportRecognizer (see detect/analyzer.py's
    _INDIA_BUILTINS), for two reasons found by probing:
    - it scores 0.1, so even next to "passport" it reached only 0.45 -
      below the 0.5 threshold, i.e. IN_PASSPORT could never be masked;
    - its pattern requires the 2nd and last characters to be 1-9, so a
      passport number with a 0 in either place would be silently missed.
    Replacing rather than stacking means the same span can never be
    reported twice. Named so it can't collide with Presidio's class name
    (see recognizers/__init__.py for why that matters)."""

    PATTERNS = [
        Pattern(
            "Passport number (context required)",
            r"\b[A-Z]\d{2}\s?\d{5}\b",
            0.15,
        )
    ]
    CONTEXT = ["passport"]

    def __init__(self):
        super().__init__(
            supported_entity="IN_PASSPORT",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            name="PassportNumberRecognizer",
        )


class ItrAcknowledgementRecognizer(PatternRecognizer):
    """Detects: Income Tax Return acknowledgement number. FP/FN risk: HIGH -
    format has changed across assessment years (historically a 15-digit
    number; newer portal formats vary). Intentionally broad + fully
    context-dependent; revisit against real (synthetic) ITR-V samples."""

    PATTERNS = [
        Pattern(
            "ITR acknowledgement number (context required)",
            r"\b\d{10,15}\b",
            0.15,
        )
    ]
    CONTEXT = ["acknowledgement", "number", "itr", "file"]  # "file", not "filing" - see module docstring

    def __init__(self):
        super().__init__(
            supported_entity="ITR_ACK_NUMBER",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            name="ItrAcknowledgementRecognizer",
        )


class RationCardNumberRecognizer(PatternRecognizer):
    """Detects: ration card number. FP/FN risk: HIGH - no national standard,
    state-issued formats vary widely (some purely numeric, some
    alphanumeric). Intentionally broad + fully context-dependent.

    Must contain at least one digit. Without that, any 8-15 letter word
    containing "ration" or "card" was masked as a ration card number -
    found on a synthetic bank statement, where the standard column header
    "Narration" became RATION_CARD_NUMBER_A ("Registration" would too).
    Presidio matches context words as SUBSTRINGS of nearby lemmas, and a
    candidate word counts as its own neighbor. No real ration card number
    is letters only."""

    PATTERNS = [
        Pattern(
            "Ration card number (context required)",
            r"\b(?=[A-Z0-9]*\d)[A-Z0-9]{8,15}\b",
            0.15,
        )
    ]
    CONTEXT = ["ration", "card"]

    def __init__(self):
        super().__init__(
            supported_entity="RATION_CARD_NUMBER",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            name="RationCardNumberRecognizer",
        )
