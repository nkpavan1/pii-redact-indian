"""AIS (Annual Information Statement) portal-specific identifiers.

The AIS/TIS "Download ID" printed on every downloaded AIS/TIS PDF/JSON is
a concatenation of the assessee's PAN + the download date (YYYYMMDD) +
download time (HHMM), e.g. `ABCDE1234F202501151030` for PAN `ABCDE1234F`,
downloaded 2025-01-15 at 10:30. It is effectively a PAN with extra digits
appended, and just as sensitive - but Presidio's own IN_PAN recognizer
never matches it: every IN_PAN pattern ends in `\\b` (a word-boundary
assertion), and there is NO word boundary between the PAN's last letter
and the immediately-following date digits - letters and digits are both
"word" characters to a regex, and `\\b` only fires at a transition between
a word character and a non-word one. Confirmed directly, not assumed:
none of Presidio's IN_PAN patterns match any prefix of a real Download ID
string, precisely because of this. This recognizer exists specifically to
close that gap - found via a real user report on an actual AIS document.
"""

from __future__ import annotations

from datetime import date

from presidio_analyzer import Pattern, PatternRecognizer


class AisDownloadIdRecognizer(PatternRecognizer):
    """Detects: AIS/TIS Download ID (22 chars: 10-char PAN + 8-digit
    YYYYMMDD + 4-digit HHMM). FP/FN risk: LOW - the fixed 22-character
    shape with a PAN-shaped prefix is already highly distinctive;
    validate_result additionally checks the embedded date/time are
    plausible (real year/month/day/hour/minute ranges), pushing an
    implausible match's score to 0 rather than relying on shape alone.
    No formal checksum exists for this concatenated ID, but date/time
    plausibility validation serves the same false-positive-filtering
    purpose."""

    PATTERNS = [
        Pattern(
            "AIS Download ID (PAN + YYYYMMDD + HHMM)",
            r"\b[A-Z]{5}[0-9]{4}[A-Z]\d{12}\b",
            0.5,
        )
    ]
    CONTEXT = ["download", "id", "ais", "acknowledgement"]

    def __init__(self):
        super().__init__(
            supported_entity="AIS_DOWNLOAD_ID",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            name="AisDownloadIdRecognizer",
        )

    def validate_result(self, pattern_text: str) -> bool | None:
        digits = pattern_text[10:]
        year, month, day = int(digits[0:4]), int(digits[4:6]), int(digits[6:8])
        hour, minute = int(digits[8:10]), int(digits[10:12])

        if not (2000 <= year <= 2099 and 0 <= hour <= 23 and 0 <= minute <= 59):
            return False
        try:
            date(year, month, day)
        except ValueError:
            return False
        return True
