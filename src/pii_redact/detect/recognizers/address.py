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

import regex
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


# --- PIN-code-anchored addresses (no "address" label needed)
#
# An Indian address almost always ends in a 6-digit PIN code (first digit
# 1-9, sometimes written "560 038"). Anchoring on it finds addresses that
# have no "address" label nearby - the common case in chat ("send it to 12
# MG Road, Indiranagar, Bengaluru 560038") and in letterheads.
#
# Pieces:
# - a word is an address token: "B-204", "No.12", "#12", "H.O", "3rd".
# - a segment is 1-6 such words ending in a comma: "12 MG Road,".
# - the place is 1-4 words right before the PIN (city/state).
# - an optional trailing state or country in capitals after the PIN.
# Case matters for that last part, so these patterns are compiled without
# Presidio's default IGNORECASE.
#
# The place right before the PIN must start with a capital letter (a city
# or state), which keeps ordinary sentences ending in a 6-digit number
# ("..., and the fee is 450000") out.
#
# Known behavior, accepted (the safe direction): a leading phrase can be
# swept into the first segment ("Send it to 12 MG Road, ..." takes "Send it
# to" too - up to six words), and "Word - 123456" matches for capitalized
# words not on the banking list below.
_PIN = r"(?<!\d)(?<!\d[.,])[1-9]\d{2}[ \t]?\d{3}(?![\d,]?\d)"
_ADDRESS_WORD = r"[\w#/.'&()\-]+"
_SEGMENT = rf"{_ADDRESS_WORD}(?:[ \t]+{_ADDRESS_WORD}){{0,5}}[ \t]*,[ \t]*"
_PLACE = rf"[A-Z][\w.'\-]*(?:[ \t]+{_ADDRESS_WORD}){{0,3}}"
_TRAILING_REGION = r"(?:[ \t]*,[ \t]*[A-Z][A-Za-z]+(?:[ \t]+[A-Z][A-Za-z]+){0,2}(?![A-Za-z]))?"
# Transaction prefixes that are followed by a dash and 6 digits on bank
# statements, and must not be read as "City - PIN".
_NOT_PLACES = r"(?i:neft|imps|rtgs|upi|atm|pos|chq|cheque|ref|txn|inv|invoice|order|id|no|emi|otp)"


class PinCodeAddressRecognizer(PatternRecognizer):
    """IN_ADDRESS anchored on a PIN code.

    - "12 MG Road, Indiranagar, Bengaluru 560038" (segments + place + PIN):
      0.6, masked with no context word.
    - "BHOPAL - 462001" (a place, a dash, a PIN - one line of a letterhead):
      0.5, masked; banking prefixes (NEFT-..., IMPS-...) excluded.
    - "PIN 560038" / "pincode is 560038": 0.5, the number only.
    The existing AddressRecognizer still handles labeled addresses."""

    PATTERNS = [
        Pattern(
            "Address ending in a PIN code",
            rf"(?<![\w#/.'&()\-])(?:{_SEGMENT}){{1,6}}{_PLACE}[ \t]*[-,]?[ \t]*{_PIN}{_TRAILING_REGION}",
            0.6,
        ),
        Pattern(
            "Place - PIN code",
            rf"(?<![\w#/.'&()\-])(?!{_NOT_PLACES}\b)[A-Za-z]{{3,}}(?:[ \t]+[A-Za-z]{{3,}}){{0,2}}[ \t]*-[ \t]*{_PIN}",
            0.5,
        ),
        Pattern(
            "PIN code",
            # The keyword stays in the text ("pincode is IN_ADDRESS_A");
            # only the number is matched.
            rf"(?<=(?i:\bpin[ \t]*(?:code)?(?:[ \t]+(?:is|no\.?|number))?)[ \t]*[:.\-]?[ \t]*){_PIN}",
            0.5,
        ),
    ]

    def __init__(self):
        super().__init__(
            supported_entity="IN_ADDRESS",
            patterns=self.PATTERNS,
            name="PinCodeAddressRecognizer",
            global_regex_flags=regex.MULTILINE,
        )
