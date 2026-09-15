"""Checksum validators used as a second-pass filter on regex-matched
candidates, to cut false positives/negatives per the project instructions
("Aadhaar/PAN precision" - regex confirms format, not the checksum digit).
"""

from __future__ import annotations

# Verhoeff algorithm multiplication, permutation, and inverse tables.
# Reference: J. Verhoeff, "Error Detecting Decimal Codes" (1969); this is the
# standard table set used for Aadhaar's check digit.
_D_TABLE = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_P_TABLE = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def verhoeff_is_valid(number: str) -> bool:
    """Validate a numeric string's trailing check digit with the Verhoeff
    algorithm. Used for IN_AADHAAR (12 digits, last digit is the check
    digit)."""
    if not number.isdigit():
        return False
    digits = [int(d) for d in reversed(number)]
    checksum = 0
    for i, digit in enumerate(digits):
        checksum = _D_TABLE[checksum][_P_TABLE[i % 8][digit]]
    return checksum == 0


# No luhn_is_valid here: it existed only to back a custom CREDIT_CARD
# recognizer that turned out to duplicate (and, worse, name-collide with)
# Presidio's own built-in CreditCardRecognizer, which already does Luhn
# validation internally - see detect/recognizers/__init__.py's note. Re-add
# a Luhn validator here only if a genuinely new checksum-validated numeric
# ID is needed that Presidio doesn't already cover.
