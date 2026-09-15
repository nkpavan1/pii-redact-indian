"""Postal address - free-text with no fixed structure, unlike every other
recognizer in this project. Presidio has no built-in for this (checked
`presidio_analyzer.predefined_recognizers` directly - only
`MacAddressRecognizer` exists, an unrelated network identifier). spaCy's
own NER only catches fragments of a real address (confirmed directly: on
a real AIS document's address line, it tagged just the trailing state
name "PRADESH" as LOCATION at 0.85 - and LOCATION is deliberately excluded
from every allow-list in this project anyway, since a city/place name can
be computation-relevant elsewhere). Neither covers the address as a whole,
which is what actually needs to disappear.

Found via a real user report on an AIS document: the "Address" field's
value (house number, street, locality, city, state, PIN code all run
together, e.g. "B-204, SUNRISE APARTMENTS,MAIN ROAD,RAMPUR
H.O,RAMPUR,BHOPAL,462001,MADHYA PRADESH") was not being redacted at
all, because nothing in Presidio's built-ins or this project's other
recognizers targets free-text address blocks.

CONTEXT is a single word, verified as its own lemma (see banking.py's
module docstring for the two ways this goes wrong): "address" self-
lemmatizes to "address" in context - confirmed directly with spaCy, not
assumed.
"""

from __future__ import annotations

from presidio_analyzer import Pattern, PatternRecognizer


class AddressRecognizer(PatternRecognizer):
    """Detects: a run of 20+ typical address characters (letters, digits,
    spaces, commas, periods, hyphens, slashes), filtered by nearby
    "address" context. FP/FN risk: HIGH without context, by design - any
    sufficiently long ordinary sentence could match the bare pattern; the
    low base score plus required context is what keeps this from firing
    on unrelated body text (confirmed directly: a document section header
    of similar length and character makeup does NOT cross the score
    threshold without "address" nearby). No checksum exists for free text.
    Deliberately does NOT try to parse or validate address structure (no
    fixed format exists across Indian states) - it redacts the whole
    matched span, favoring completeness over precision once context
    confirms this is actually an address field."""

    PATTERNS = [
        Pattern(
            "Address block (context required)",
            r"\b[\w][\w\s,./\-]{19,}\b",
            0.15,
        )
    ]
    CONTEXT = ["address"]

    def __init__(self):
        super().__init__(
            supported_entity="IN_ADDRESS",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            name="AddressRecognizer",
        )
