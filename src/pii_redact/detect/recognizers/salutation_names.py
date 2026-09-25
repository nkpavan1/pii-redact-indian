"""Person names that follow a title (Mr, Mrs, Shri, Smt, Dr., ...) - the
case spaCy's NER misses most on Indian documents.

Found on a real bank statement: spaCy returned no PERSON at all for an
all-caps name with a leading initial after a title ("MR. R RAJESH KUMAR"
is the fictional equivalent), and where it did find part of such a name it
left the initials behind. Indian documents print names this way
constantly: titles, initials first or last, all caps.

The title itself is not part of the match (a lookbehind), so the output
reads "MR. PERSON_A" and reversal restores just the name.

Deliberate exclusions, each a real false-positive source:
- "DR" and "MS" count only with a period ("Dr.", "Ms."). A bare "DR" is
  the debit marker on every bank statement ("DR NEFT TRANSFER"), and "MS
  Excel" is not a person.
- A word from _NOT_NAMES ends the name, so "MR RAJESH KUMAR SAVINGS
  ACCOUNT" stops before "SAVINGS".

Case matters here (a name word starts with a capital), so these patterns
are compiled without Presidio's default IGNORECASE; the title alone is
matched case-insensitively.
"""

from __future__ import annotations

import regex
from presidio_analyzer import Pattern, PatternRecognizer

_TITLE = r"(?i:mrs|mr|miss|shri|sri|smt|kumari|kum)\.?|(?i:dr|ms)\."

# Words that are never part of a name in the documents this tool sees -
# statement headers and sentence glue in capitals.
_NOT_NAMES = (
    "ACCOUNT|SAVINGS|CURRENT|BANK|BRANCH|CUSTOMER|ADDRESS|DATE|NUMBER|NO|PAN|MOBILE|PHONE|EMAIL|"
    "ID|DOB|AND|THE|OF|FOR|TO|FROM|ON|AT|IN|IS|WAS|HAS|WITH|BY|DEAR|SIR|MADAM"
)
_INITIAL = r"[A-Z]\.?"
_WORD = rf"(?!(?i:{_NOT_NAMES})\b)[A-Z][A-Za-z'\-]+"
_NAME = (
    rf"(?<=\b(?:{_TITLE})[ \t]+)"          # right after a title (not included)
    rf"(?:{_INITIAL}[ \t]*){{0,3}}"         # leading initials: "R ", "A. P. J. "
    rf"{_WORD}"                             # first name word
    rf"(?:[ \t]+(?:{_INITIAL}[ \t]+)?{_WORD}){{0,2}}"  # up to two more, maybe with a middle initial
    rf"(?:[ \t]+[A-Z]\.?(?![A-Za-z/]))?"    # trailing initial: "RAJESH K" (not the W of "W/O")
    r"(?![A-Za-z])"
)


class SalutationNameRecognizer(PatternRecognizer):
    """PERSON after a title. Score 0.85, the same as spaCy's PERSON, since
    a title is at least as strong a signal as NER's own confidence."""

    PATTERNS = [Pattern("Name after a title", _NAME, 0.85)]

    def __init__(self):
        super().__init__(
            supported_entity="PERSON",
            patterns=self.PATTERNS,
            name="SalutationNameRecognizer",
            global_regex_flags=regex.MULTILINE,
        )
