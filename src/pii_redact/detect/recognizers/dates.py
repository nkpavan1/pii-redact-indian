"""Date of birth - a context-scoped variant of "a date", per the project
instructions' entity-scoping rule: bare DATE_TIME must never be blanket-
redacted (a transaction date or holding-period date must survive), but a
date genuinely identified as someone's DOB should be. Presidio's own
DATE_TIME recognizer doesn't distinguish the two; this recognizer doesn't
either, on its own - it relies entirely on nearby context words to tell
them apart, emitting a SEPARATE entity type (`IN_DATE_OF_BIRTH`) so
document-type allow-lists can safely include this one without touching
bare DATE_TIME anywhere (see config/allowlists.py).

CONTEXT is single words only, never phrases - see banking.py's module
docstring for why (Presidio's context matcher checks individual lemmas,
not phrases). Deliberately narrow: only "dob", "birth", "bear" - NOT the
word "date" itself, since that would boost on every date in every
document (a bank statement mentioning "date" near a transaction date is
exactly the false positive this recognizer must not create).

VERIFIED, NOT ASSUMED: "bear", not "born". Presidio compares each context
list entry as a literal string against the LEMMA of each surrounding
document token - it does not lemmatize the context list itself. spaCy
lemmatizes "born"/"Born" to "bear" (its base verb form, as in "to bear a
child"), so a context list containing the surface form "born" silently
never matches anything - confirmed directly: context=["born"] produced no
score boost on "Born on 1990-08-15" in a real AnalyzerEngine, while
context=["bear"] boosted it exactly as expected. Same root cause as the
multi-word-phrase bug in banking.py, one level subtler: single words are
necessary but not sufficient - they must also be the correct lemma. Two
other recognizers had the identical bug (see other_documents.py:
"driving" -> lemma "drive", "filing" -> lemma "file") - before adding any
new context word, check its lemma with spaCy rather than assuming the
surface form is also the lemma.

GUARDED AGAINST, per real user report on an AIS document: Indian tax
documents routinely label TDS/TCS quarters as "Q1(Apr-Jun)", "Q4(Jan-Mar)",
etc. - a month-RANGE, not a date, and must never match. The day-month-year
and month-day-year patterns below both reject a month immediately followed
by a dash and a second month name, specifically to exclude this shape.
(The exact regex path that matched the originally-reported "Q4(Jan-Mar)"
wasn't conclusively reproduced by manual tracing against these patterns -
this guard is added proactively because the shape is common and
predictable in this document class, not because the precise prior match
was pinned down. If it recurs, the actual extracted line of text is needed
to diagnose further - the true cause could also be in a PDF extraction
reading-order/adjacency quirk rather than the regex itself.)
"""

from __future__ import annotations

from presidio_analyzer import Pattern, PatternRecognizer

_MONTHS = "Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec"
_NOT_A_MONTH_RANGE = rf"(?!\s*[-–]\s*(?:{_MONTHS}))"


class DateOfBirthRecognizer(PatternRecognizer):
    """Detects: a date in one of several common formats (DD/MM/YYYY,
    DD-MM-YYYY, DD.MM.YYYY, YYYY-MM-DD, "15 Aug 1990", "Aug 15, 1990"),
    filtered by nearby DOB-specific context words. FP/FN risk: HIGH
    without context, by design - date-shaped strings are extremely
    common and mean nothing on their own (see BankAccountNumberRecognizer
    for the same "low base score, context does the real work" pattern).
    No checksum exists for a date."""

    PATTERNS = [
        Pattern(
            "Numeric date (context required)",
            r"\b\d{1,2}[/\-.]\d{1,2}[/\-.]\d{2,4}\b",
            0.2,
        ),
        Pattern(
            "ISO date (context required)",
            r"\b\d{4}-\d{1,2}-\d{1,2}\b",
            0.2,
        ),
        Pattern(
            "Day Month Year (context required)",
            rf"\b\d{{1,2}}[\s\-]+(?:{_MONTHS})[a-z]*{_NOT_A_MONTH_RANGE}[\s\-,]+\d{{4}}\b",
            0.3,
        ),
        Pattern(
            "Month Day, Year (context required)",
            rf"\b(?:{_MONTHS})[a-z]*{_NOT_A_MONTH_RANGE}[\s\-]+\d{{1,2}},?[\s\-]+\d{{4}}\b",
            0.3,
        ),
    ]
    CONTEXT = ["dob", "birth", "bear"]  # "bear", not "born" - see module docstring

    def __init__(self):
        super().__init__(
            supported_entity="IN_DATE_OF_BIRTH",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            name="DateOfBirthRecognizer",
        )
