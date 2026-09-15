"""TAN, CIN - structured Indian business/tax identifiers with a fixed
format but no checksum implemented here (see per-recognizer notes).

GSTIN is deliberately NOT here: Presidio's own built-in `InGstinRecognizer`
(entity `IN_GSTIN`) already exists in this presidio-analyzer release, with
a real checksum validator (`validate_result` does an actual GSTIN checksum,
not just a format match) - strictly better than a hand-rolled duplicate
would be. Discovered by an end-to-end smoke test crash (see
detect/recognizers/__init__.py's note on the class-name collision that
crash surfaced) - always check whether Presidio already covers an entity
before adding a custom recognizer for it, per the project instructions.

CONTEXT lists are single words only - see banking.py's module docstring
for why (multi-word phrases don't match Presidio's context matcher at all).
"""

from __future__ import annotations

from presidio_analyzer import Pattern, PatternRecognizer


class TanRecognizer(PatternRecognizer):
    """Detects: Tax Deduction and Collection Account Number (4 letters +
    5 digits + 1 letter). FP/FN risk: low - the 4-letter/5-digit/1-letter
    shape is fairly distinctive, but no checksum is validated."""

    PATTERNS = [Pattern("TAN (format)", r"\b[A-Z]{4}\d{5}[A-Z]\b", 0.6)]
    CONTEXT = ["tan", "tax", "deduction", "account", "number"]

    def __init__(self):
        super().__init__(
            supported_entity="TAN",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            name="TanRecognizer",
        )


class CinRecognizer(PatternRecognizer):
    """Detects: Corporate Identification Number (21 chars: L/U + 5-digit
    industry code + 2-letter state code + 4-digit year + 3-letter ownership
    type + 6-digit registration number). FP/FN risk: low, the length and
    fixed sub-structure make accidental matches rare. No checksum digit
    exists in the CIN spec, so none is validated (there is none to
    validate)."""

    PATTERNS = [
        Pattern(
            "CIN (format)",
            r"\b[LU]\d{5}[A-Z]{2}\d{4}[A-Z]{3}\d{6}\b",
            0.7,
        )
    ]
    CONTEXT = ["cin", "corporate", "identification", "number"]

    def __init__(self):
        super().__init__(
            supported_entity="CIN",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            name="CinRecognizer",
        )
